"""
Безпечне логування: єдина точка, через яку проходять ВСІ записи журналу.

Механізм складається з трьох частин (див. configure_secure_logging):

  1. PiiSanitizingFilter  - фільтр на handler-і: санітизує повідомлення,
                            аргументи, extra-поля, текст exception і stack trace.
  2. SecureFormatter /    - форматувальники (текстовий і JSON), які ще раз
     SecureJsonFormatter    санітизують фінальний вивід (defence in depth) і
                            не руйнують формат: correlation_id та operation лишаються.
  3. Flask-хуки           - correlation ID для кожного запиту та access-лог
                            без query string і без тіла запиту/відповіді.

Тому автор нового коду не може "забути" замаскувати значення: захист діє на рівні
handler-а, а не окремого controller/service.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from privacy.sanitizer import (
    REDACTED, register_secret, sanitize_text, sanitize_value,
)

# Стандартні атрибути LogRecord: все інше в record.__dict__ вважаємо extra-полями.
_STD_ATTRS = frozenset(logging.makeLogRecord({}).__dict__) | {"message", "asctime", "taskName"}

_CORRELATION_RE = re.compile(r"^[A-Za-z0-9\-]{8,64}$")
TEXT_FORMAT = "%(asctime)s %(levelname)s [%(correlation_id)s] %(name)s: %(message)s"


def _extra_fields(record: logging.LogRecord) -> dict:
    return {k: v for k, v in record.__dict__.items() if k not in _STD_ATTRS}


def _current_correlation_id() -> str:
    try:
        from flask import g, has_request_context
        if has_request_context():
            return getattr(g, "correlation_id", "-")
    except Exception:  # Flask може бути не імпортований у CLI-скриптах
        pass
    return "-"


current_correlation_id = _current_correlation_id


# ---------------------------------------------------------------------------
# Фільтри
# ---------------------------------------------------------------------------

class CorrelationIdFilter(logging.Filter):
    """Додає record.correlation_id (з поточного запиту Flask або '-')."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not getattr(record, "correlation_id", None):
            record.correlation_id = _current_correlation_id()
        return True


class PiiSanitizingFilter(logging.Filter):
    """Санітизує запис журналу на місці, до того як його побачить будь-який formatter."""

    def filter(self, record: logging.LogRecord) -> bool:
        # 1. Повідомлення разом з аргументами (%s-підстановки, f-рядки, DTO через str()).
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        record.msg = sanitize_text(message)
        record.args = ()

        # 2. Extra-поля (logger.info("...", extra={...})), у т.ч. вкладені DTO/dict.
        for key, value in _extra_fields(record).items():
            if key == "correlation_id":
                continue
            setattr(record, key, sanitize_value(key, value))

        # 3. Exception: Formatter бере готовий exc_text замість того, щоб будувати свій.
        if record.exc_info and record.exc_info[0] is not None:
            raw = "".join(traceback.format_exception(*record.exc_info)).rstrip()
            record.exc_text = sanitize_text(raw)
        elif record.exc_text:
            record.exc_text = sanitize_text(record.exc_text)
        if record.stack_info:
            record.stack_info = sanitize_text(record.stack_info)
        return True


# ---------------------------------------------------------------------------
# Форматувальники
# ---------------------------------------------------------------------------

class SecureFormatter(logging.Formatter):
    """Текстовий формат; фінальний рядок санітизується ще раз (idempotent)."""

    def __init__(self, fmt: str = TEXT_FORMAT, datefmt: Optional[str] = None):
        super().__init__(fmt=fmt, datefmt=datefmt)

    def format(self, record: logging.LogRecord) -> str:
        if not getattr(record, "correlation_id", None):
            record.correlation_id = _current_correlation_id()
        text = super().format(record)

        # Extra-поля (operation, payload, status ...) дописуються до першого рядка
        # як key=value; значення вже санітизовані, але перевіряються ще раз.
        extras = " ".join(
            f"{key}={json.dumps(sanitize_value(key, value), ensure_ascii=False, default=str)}"
            for key, value in _extra_fields(record).items() if key != "correlation_id"
        )
        if extras:
            head, newline, tail = text.partition("\n")
            text = f"{head} | {extras}{newline}{tail}"
        return sanitize_text(text)


class SecureJsonFormatter(logging.Formatter):
    """Один JSON-об'єкт на рядок (JSON Lines). Формат лишається валідним JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "correlation_id": getattr(record, "correlation_id", None) or _current_correlation_id(),
            "message": sanitize_text(record.getMessage()),
        }
        for key, value in _extra_fields(record).items():
            if key != "correlation_id":
                payload[key] = sanitize_value(key, value)
        if record.exc_info and record.exc_info[0] is not None:
            payload["exception"] = sanitize_text(
                record.exc_text or "".join(traceback.format_exception(*record.exc_info)).rstrip()
            )
        elif record.exc_text:
            payload["exception"] = sanitize_text(record.exc_text)
        return json.dumps(payload, ensure_ascii=False, default=lambda o: sanitize_text(repr(o)))


# ---------------------------------------------------------------------------
# Побудова handler-а та налаштування застосунку
# ---------------------------------------------------------------------------

def secure_handler(handler: Optional[logging.Handler] = None, fmt: str = "text") -> logging.Handler:
    """Робить із handler-а безпечний: correlation ID + санітизація + безпечний formatter."""
    handler = handler or logging.StreamHandler(sys.stderr)
    handler.addFilter(CorrelationIdFilter())
    handler.addFilter(PiiSanitizingFilter())
    handler.setFormatter(SecureJsonFormatter() if fmt == "json" else SecureFormatter())
    return handler


def configure_secure_logging(app=None, level: int = logging.INFO) -> None:
    """
    Підключає безпечне логування до всього застосунку.

    Змінні середовища (необов'язкові):
      LOG_FORMAT = text | json   (за замовчуванням text)
      LOG_FILE   = шлях до файлу журналу (додатково до консолі)
    """
    fmt = os.getenv("LOG_FORMAT", "text").lower()
    root = logging.getLogger()
    for old in list(root.handlers):
        root.removeHandler(old)
    root.setLevel(level)
    root.addHandler(secure_handler(logging.StreamHandler(sys.stderr), fmt))

    log_file = os.getenv("LOG_FILE")
    if log_file:
        root.addHandler(secure_handler(logging.FileHandler(log_file, encoding="utf-8"), fmt))

    # Власний access-лог (без query string) замінює стандартний рядок werkzeug.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    if app is None:
        return

    # Точні значення секретів застосунку редагуються де б не з'явились.
    register_secret(app.config.get("SECRET_KEY"))
    db_uri = str(app.config.get("SQLALCHEMY_DATABASE_URI") or "")
    m = re.match(r"^[a-z][a-z0-9+.\-]*://[^:/@]+:([^@]+)@", db_uri, re.IGNORECASE)
    if m:
        register_secret(m.group(1))

    access_logger = logging.getLogger("access")

    @app.before_request
    def _start_request():
        from flask import g, request
        incoming = request.headers.get("X-Correlation-ID", "")
        g.correlation_id = incoming if _CORRELATION_RE.match(incoming) else uuid.uuid4().hex[:16]
        g._request_started = time.perf_counter()

    @app.after_request
    def _finish_request(response):
        from flask import g, request
        started = getattr(g, "_request_started", None)
        duration_ms = round((time.perf_counter() - started) * 1000, 1) if started else None
        response.headers["X-Correlation-ID"] = getattr(g, "correlation_id", "-")
        # Лише метод, шлях (без query string), статус і тривалість: жодних тіл запиту/відповіді.
        access_logger.info(
            "request completed",
            extra={"operation": "http_request", "method": request.method,
                   "path": request.path, "status": response.status_code,
                   "duration_ms": duration_ms},
        )
        return response


# ---------------------------------------------------------------------------
# Security-події
# ---------------------------------------------------------------------------

_security_logger = logging.getLogger("security")


def log_security_event(operation: str, outcome: str, actor_id: Any = None,
                       subject_id: Any = None, reason: Optional[str] = None) -> None:
    """
    Фіксує факт операції без PII: що (operation), результат (outcome), хто (actor_id),
    над ким (subject_id), чому (reason). Час і correlation ID додає форматувальник.
    ID - це внутрішні сурогатні ключі, а не імена чи email.
    """
    _security_logger.info(
        "security event",
        extra={"operation": operation, "outcome": outcome,
               "actor_id": actor_id, "subject_id": subject_id, "reason": reason},
    )
