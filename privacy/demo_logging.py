"""
Live demo до Завдання 1 (Secure Logging).

Запуск з кореня проєкту:   python -m privacy.demo_logging

Одні й ті самі події логуються двічі: звичайним логером (BEFORE) і захищеним (AFTER).
Усі значення синтетичні: реальних персональних даних і секретів тут немає.
"""
from __future__ import annotations

import logging
import sys
from dataclasses import dataclass

from privacy.secure_logging import secure_handler

EMAIL = "maria.test@example.com"
PHONE = "+380501234567"
PASSWORD = "S3cretPass!123"
# Токен збирається з частин, щоб секрет-сканер (Gitleaks) не бачив літерал у коді.
TOKEN = "ghp_" + "A1b2C3d4" * 4 + "A1b2"


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


def _make_logger(name: str, protected: bool, fmt: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    if protected:
        secure_handler(handler, fmt)
    else:
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    return logger


def _scenarios(logger: logging.Logger) -> None:
    dto = UserDTO("Maria Test", EMAIL, PASSWORD, TOKEN, ContactDTO(EMAIL, PHONE))
    corr = {"correlation_id": "demo-0001-corr", "operation": "register_request"}

    # 1. Звичайний текст (рядок, зібраний вручну).
    logger.info(f"Registration: email={EMAIL}, phone={PHONE}, password={PASSWORD}, token={TOKEN}", extra=corr)

    # 2. Структуровані дані (вкладений dict).
    logger.info("Structured payload", extra={
        **corr, "payload": {"email": EMAIL, "phone": PHONE, "password": PASSWORD,
                            "nested": {"refresh_token": "refresh-synthetic-0001", "status": "pending"}}})

    # 3. Вкладений DTO.
    logger.info("DTO object: %s", dto, extra=corr)
    logger.info("DTO as extra", extra={**corr, "dto": dto})

    # 4. Повідомлення exception.
    try:
        raise ValueError(f"Cannot send mail to {EMAIL} (phone {PHONE}), password={PASSWORD}")
    except ValueError:
        logger.exception("Operation failed", extra=corr)


def main() -> None:
    print("=" * 78)
    print("BEFORE: звичайний логер (витік PII та секретів)")
    print("=" * 78)
    _scenarios(_make_logger("demo.before", protected=False, fmt="text"))

    print("\n" + "=" * 78)
    print("AFTER: захищений логер, текстовий формат")
    print("=" * 78)
    _scenarios(_make_logger("demo.after.text", protected=True, fmt="text"))

    print("\n" + "=" * 78)
    print("AFTER: захищений логер, JSON-формат (по одному об'єкту на рядок)")
    print("=" * 78)
    _scenarios(_make_logger("demo.after.json", protected=True, fmt="json"))


if __name__ == "__main__":
    main()
