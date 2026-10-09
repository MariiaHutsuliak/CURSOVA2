"""
Автоматизовані тести Завдання 1 (Secure Logging та маскування PII).

Тести перехоплюють ФАКТИЧНИЙ вивід логера (StringIO-handler з тим самим
secure_handler(), що й у застосунку) і перевіряють, що жодне вихідне
sensitive-значення не потрапило в текст. Усі значення синтетичні.

Запуск:  python -m pytest tests/test_secure_logging.py -v
"""
import io
import json
import logging
import uuid
from dataclasses import dataclass

import pytest
from flask import Flask

from privacy import sanitizer
from privacy.secure_logging import (
    PiiSanitizingFilter, configure_secure_logging, log_security_event, secure_handler,
)

# --- Синтетичні тестові значення (не належать реальним людям і сервісам) ----------
EMAIL = "maria.test@example.com"
PHONE = "+380501234567"
PHONE_LOCAL = "050 123 45 67"
PASSWORD = "S3cretPass!123"
# Токен збирається з частин, щоб Gitleaks не бачив літерал у коді тесту.
GH_TOKEN = "ghp_" + "A1b2C3d4" * 4 + "A1b2"
REFRESH = "refresh-synthetic-0001"
API_KEY = "key-synthetic-0002"
FULL_NAME = "Maria Test"

SENSITIVE_VALUES = [
    EMAIL, "maria.test", PHONE, "380501234567", "0501234567", "050 123 45 67",
    PASSWORD, GH_TOKEN, REFRESH, API_KEY, FULL_NAME,
]


@dataclass
class ContactDTO:
    email: str
    phone: str


@dataclass
class UserDTO:
    username: str
    email: str
    password: str
    access_token: str
    contact: ContactDTO


class PlainObject:
    """Звичайний клас без dataclass: перевіряє гілку __dict__."""

    def __init__(self):
        self.email = EMAIL
        self.phone = PHONE
        self.api_key = API_KEY


def make_dto() -> UserDTO:
    return UserDTO(FULL_NAME, EMAIL, PASSWORD, GH_TOKEN, ContactDTO(EMAIL, PHONE))


# --- Допоміжні засоби ------------------------------------------------------------

def make_logger(fmt="text", protected=True):
    """Повертає (logger, stream). protected=False - звичайний логер без захисту."""
    stream = io.StringIO()
    logger = logging.getLogger(f"test.{uuid.uuid4().hex}")
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(stream)
    if protected:
        secure_handler(handler, fmt)
    logger.addHandler(handler)
    return logger, stream


def assert_no_sensitive(output: str):
    """FAIL, якщо хоча б одне вихідне sensitive-значення потрапило до логу."""
    leaked = [v for v in SENSITIVE_VALUES if v in output]
    assert not leaked, f"У логі знайдено відкриті sensitive-значення: {leaked}\n{output}"


# --- Позитивні тести: різні формати -----------------------------------------------

def test_plain_text_message_masks_pii_and_redacts_secrets():
    logger, stream = make_logger("text")
    logger.info(f"Registration: email={EMAIL}, phone={PHONE}, password={PASSWORD}, token={GH_TOKEN}")
    out = stream.getvalue()

    assert_no_sensitive(out)
    assert "m***@example.com" in out          # email маскується частково
    assert "567" in out                        # лишились останні 3 цифри телефону
    assert out.count("[REDACTED]") >= 2        # пароль і токен повністю редаговані


def test_percent_args_and_local_phone_format_are_sanitized():
    logger, stream = make_logger("text")
    logger.warning("Call back %s or %s", PHONE_LOCAL, EMAIL)
    out = stream.getvalue()
    assert_no_sensitive(out)
    assert "m***@example.com" in out


def test_structured_json_log_is_valid_json_and_sanitized():
    logger, stream = make_logger("json")
    logger.info("Structured payload", extra={
        "correlation_id": "corr-1234-abcd", "operation": "register_request",
        "payload": {"email": EMAIL, "phone": PHONE, "password": PASSWORD,
                    "nested": {"refresh_token": REFRESH, "api_key": API_KEY, "status": "pending"}},
    })
    line = stream.getvalue().strip()
    data = json.loads(line)                    # формат не зруйновано

    assert_no_sensitive(line)
    assert data["payload"]["email"] == "m***@example.com"
    assert data["payload"]["phone"] == "+*********567"   # не знищується другим проходом
    assert data["payload"]["password"] == "[REDACTED]"
    assert data["payload"]["nested"]["refresh_token"] == "[REDACTED]"
    assert data["payload"]["nested"]["api_key"] == "[REDACTED]"
    # діагностична цінність збережена
    assert data["correlation_id"] == "corr-1234-abcd"
    assert data["operation"] == "register_request"
    assert data["payload"]["nested"]["status"] == "pending"
    assert data["level"] == "INFO" and "timestamp" in data


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_exception_message_and_traceback_are_sanitized(fmt):
    logger, stream = make_logger(fmt)
    try:
        raise ValueError(f"Cannot send mail to {EMAIL} (phone {PHONE}), password={PASSWORD}")
    except ValueError:
        logger.exception("Operation failed")
    out = stream.getvalue()

    assert_no_sensitive(out)
    assert "ValueError" in out                 # технічний тип помилки зберігся
    assert "Traceback" in out or fmt == "json"
    if fmt == "json":
        assert "ValueError" in json.loads(out.strip().splitlines()[-1])["exception"]


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_nested_dto_via_str_and_via_extra(fmt):
    logger, stream = make_logger(fmt)
    dto = make_dto()
    logger.info("DTO object: %s", dto)
    logger.info("DTO as extra", extra={"dto": dto, "plain": PlainObject()})
    out = stream.getvalue()
    assert_no_sensitive(out)


def test_secrets_in_url_headers_and_query_string():
    logger, stream = make_logger("text")
    logger.info(f"GET /export?token={GH_TOKEN}&email={EMAIL} Authorization: Bearer {GH_TOKEN}")
    logger.info("DB: postgresql://app_user:SuperSecretDbPass9@localhost:5432/bookstore")
    out = stream.getvalue()
    assert_no_sensitive(out)
    assert "SuperSecretDbPass9" not in out
    assert "app_user" in out                   # імена користувача БД не секрет, діагностика збережена


def test_registered_application_secret_is_redacted_anywhere():
    secret = "app-secret-key-synthetic-77"
    sanitizer.register_secret(secret)
    try:
        logger, stream = make_logger("text")
        logger.info(f"Config dump: {secret}")
        assert secret not in stream.getvalue()
    finally:
        sanitizer.clear_registered_secrets()


def test_diagnostic_data_is_not_destroyed():
    """Дати, IP, довгі числові ID та кількості не повинні маскуватися як телефон."""
    logger, stream = make_logger("text")
    logger.info("2026-10-09 14:55:28 from 192.168.1.10 order 1696850000 qty 12 correlation_id=3f2a9c10b4d1")
    out = stream.getvalue()
    for kept in ("2026-10-09 14:55:28", "192.168.1.10", "1696850000", "3f2a9c10b4d1"):
        assert kept in out


def test_masking_functions_are_idempotent():
    for func, value in ((sanitizer.mask_email, EMAIL), (sanitizer.mask_phone, PHONE),
                        (sanitizer.mask_name, FULL_NAME)):
        once = func(value)
        assert func(once) == once


def test_sanitization_is_idempotent():
    once = sanitizer.sanitize_text(f"{EMAIL} {PHONE} password={PASSWORD} username={FULL_NAME}")
    assert sanitizer.sanitize_text(once) == once


def test_unquoted_full_name_is_fully_masked_but_following_text_is_kept():
    logger, stream = make_logger("text")
    logger.info(f"user username={FULL_NAME} created, role=operator")
    out = stream.getvalue()
    assert "Maria" not in out and "Test" not in out      # ні ім'я, ні прізвище
    assert "M*** T***" in out
    assert "created, role=operator" in out               # решта діагностики не зачеплена


def test_text_format_keeps_correlation_id_and_level():
    logger, stream = make_logger("text")
    logger.error("boom", extra={"correlation_id": "corr-9999-zzzz"})
    out = stream.getvalue()
    assert "ERROR" in out and "[corr-9999-zzzz]" in out


def test_policy_forbidden_and_masked_keys():
    for key in ("password", "reset_token", "Access_Token", "refresh_token", "api_key",
                "SECRET_KEY", "password_hash", "session_id", "Authorization"):
        assert sanitizer.is_forbidden_key(key), key
    for key in ("correlation_id", "operation", "outcome", "actor_id", "status", "path"):
        assert not sanitizer.is_forbidden_key(key), key
    assert sanitizer.sanitize_value("email", EMAIL) == "m***@example.com"
    assert sanitizer.sanitize_value("phone", PHONE) == "+*********567"
    assert sanitizer.sanitize_value("full_name", FULL_NAME) == "M*** T***"
    assert sanitizer.sanitize_value("password", PASSWORD) == "[REDACTED]"


# --- Негативні сценарії: тест має падати, якщо захисту немає ----------------------

def test_negative_control_unprotected_logger_leaks_everything():
    """
    Контроль: ті самі повідомлення БЕЗ захисту дійсно містять sensitive-значення.
    Це доводить, що assert_no_sensitive здатний виявити витік (тест не "порожній").
    """
    logger, stream = make_logger(protected=False)
    logger.info(f"Registration: email={EMAIL}, phone={PHONE}, password={PASSWORD}, token={GH_TOKEN}")
    logger.info("DTO object: %s", make_dto())
    out = stream.getvalue()
    with pytest.raises(AssertionError):
        assert_no_sensitive(out)
    for v in (EMAIL, PHONE, PASSWORD, GH_TOKEN):
        assert v in out


def test_negative_filter_removed_means_leak_detected():
    """Якщо прибрати фільтр з handler-а, перевірка відразу ловить витік."""
    logger, stream = make_logger("text")
    handler = logger.handlers[0]
    handler.filters = [f for f in handler.filters if not isinstance(f, PiiSanitizingFilter)]
    handler.setFormatter(logging.Formatter("%(message)s"))      # без SecureFormatter
    logger.info("DTO object: %s", make_dto())
    with pytest.raises(AssertionError):
        assert_no_sensitive(stream.getvalue())


# --- Інтеграція з Flask: access-лог, correlation ID, security events -------------

@pytest.fixture
def flask_log_env():
    """Окремий мінімальний Flask-застосунок; root-логери повертаються у вихідний стан."""
    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret-key-synthetic-123"

    @app.route("/ping", methods=["GET", "POST"])
    def ping():
        logging.getLogger("demo").info(f"Processing email={EMAIL} phone={PHONE}")
        log_security_event("export", "success", actor_id=7, subject_id=7)
        return "ok"

    configure_secure_logging(app)
    stream = io.StringIO()
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(secure_handler(logging.StreamHandler(stream), "json"))
    try:
        yield app, stream
    finally:
        for h in list(root.handlers):
            root.removeHandler(h)
        for h in saved_handlers:
            root.addHandler(h)
        root.setLevel(saved_level)
        sanitizer.clear_registered_secrets()


def test_access_log_has_no_query_string_or_body(flask_log_env):
    app, stream = flask_log_env
    resp = app.test_client().post(
        f"/ping?email={EMAIL}&token={GH_TOKEN}", data={"password": PASSWORD, "phone": PHONE})
    out = stream.getvalue()

    assert resp.status_code == 200
    assert_no_sensitive(out)
    records = [json.loads(line) for line in out.strip().splitlines()]
    access = [r for r in records if r.get("operation") == "http_request"]
    assert len(access) == 1
    assert access[0]["path"] == "/ping" and access[0]["status"] == 200
    assert access[0]["method"] == "POST"
    assert "?" not in access[0]["path"]


def test_correlation_id_is_propagated_to_all_records_and_header(flask_log_env):
    app, stream = flask_log_env
    resp = app.test_client().get("/ping", headers={"X-Correlation-ID": "client-corr-0001"})
    records = [json.loads(line) for line in stream.getvalue().strip().splitlines()]

    assert resp.headers["X-Correlation-ID"] == "client-corr-0001"
    assert len(records) >= 3
    assert {r["correlation_id"] for r in records} == {"client-corr-0001"}


def test_invalid_incoming_correlation_id_is_replaced(flask_log_env):
    app, stream = flask_log_env
    resp = app.test_client().get("/ping", headers={"X-Correlation-ID": "bad id with spaces!"})
    assert resp.headers["X-Correlation-ID"] != "bad id with spaces!"
    assert len(resp.headers["X-Correlation-ID"]) == 16


def test_application_secret_key_is_registered_and_redacted(flask_log_env):
    _, stream = flask_log_env
    logging.getLogger("demo").info("leak attempt: test-secret-key-synthetic-123")
    assert "test-secret-key-synthetic-123" not in stream.getvalue()


def test_security_event_contains_only_safe_fields(flask_log_env):
    app, stream = flask_log_env
    app.test_client().get("/ping")
    records = [json.loads(line) for line in stream.getvalue().strip().splitlines()]
    event = next(r for r in records if r["logger"] == "security")

    assert event["operation"] == "export" and event["outcome"] == "success"
    assert event["actor_id"] == 7 and event["subject_id"] == 7
    assert event["correlation_id"] != "-" and "timestamp" in event
    assert not {"email", "phone", "username", "password"} & set(event)


def test_real_application_has_secure_logging_installed():
    """Справжній app.py підключає централізований механізм і не використовує basicConfig."""
    import app as bookstore_app  # noqa: F401  (імпорт запускає configure_secure_logging)
    assert bookstore_app.app is not None
    source = open(bookstore_app.__file__, encoding="utf-8").read()
    assert "configure_secure_logging(app)" in source
    assert "logging.basicConfig" not in source     # старий небезпечний спосіб прибрано
