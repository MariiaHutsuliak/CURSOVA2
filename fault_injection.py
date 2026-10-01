"""
Лабораторна робота №2, Завдання 2 — контрольована симуляція відмови
зовнішньої залежності (PostgreSQL) через тестову конфігурацію.

Керується змінною середовища DB_FAULT_MODE:
    none    — нормальна робота (за замовчуванням)
    error   — імітує обрив з'єднання з БД / HTTP 5xx-подібну відмову
              (реалістичний sqlalchemy.exc.OperationalError)
    timeout — імітує зависання запиту до БД (штучна затримка),
              після чого теж завершується як OperationalError
              (типова поведінка при вичерпанні connection/statement timeout)

Це НЕ вимкнення всього застосунку — ламається керовано лише виклик до БД
у конкретному місці, де викликається maybe_inject_fault().
"""
import os
import time
import logging
from sqlalchemy.exc import OperationalError

logger = logging.getLogger("fault_injection")

DB_FAULT_MODE_ENV = "DB_FAULT_MODE"
TIMEOUT_DELAY_SECONDS = 2.0  # штучна затримка для режиму timeout


def get_fault_mode():
    return os.getenv(DB_FAULT_MODE_ENV, "none").lower()


def maybe_inject_fault():
    """Викликається безпосередньо перед зверненням до БД."""
    mode = get_fault_mode()

    if mode == "error":
        logger.warning("[FAULT INJECTION] Симуляція відмови БД: error (OperationalError)")
        raise OperationalError(
            "Симульована відмова залежності (DB_FAULT_MODE=error): "
            "з'єднання з PostgreSQL розірвано",
            params=None,
            orig=Exception("simulated connection refused"),
        )

    if mode == "timeout":
        logger.warning(
            f"[FAULT INJECTION] Симуляція таймауту БД: затримка {TIMEOUT_DELAY_SECONDS}с, потім відмова"
        )
        time.sleep(TIMEOUT_DELAY_SECONDS)
        raise OperationalError(
            "Симульований таймаут залежності (DB_FAULT_MODE=timeout): "
            "перевищено час очікування відповіді від PostgreSQL",
            params=None,
            orig=Exception("simulated statement timeout"),
        )

    # mode == "none" -> нічого не робимо, нормальна робота