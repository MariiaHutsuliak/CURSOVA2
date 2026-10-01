"""
Лабораторна робота №2, Завдання 2 — механізм стійкості: обмежений Retry
з backoff та контрольований Fallback.

Параметри Retry винесені в аргументи декоратора та явно обґрунтовані:

    max_attempts=3        — не більше 3 спроб разом з першою. Досить, щоб
                             пережити короткочасний "гикавка" мережі/БД,
                             але не настільки багато, щоб суттєво
                             затримувати відповідь користувачу.
    base_delay_seconds=0.3 — перша затримка між спробами.
    backoff_factor=2       — експоненційне зростання затримки (0.3s -> 0.6s).

Навіщо саме такі обмеження (захист від retry storm):
    Якщо БД вже перевантажена або недоступна, миттєві повтори без
    обмежень і без затримки (retry storm) лише мультиплікують кількість
    запитів до неї — кожен клієнт, що зазнав відмови, одразу ж повторює
    запит, що ще сильніше навантажує і без того проблемну залежність,
    заважаючи їй відновитись. Обмежена кількість спроб + зростаюча
    затримка (backoff) дають залежності час на відновлення й запобігають
    лавиноподібному зростанню навантаження.
"""
import time
import logging
from functools import wraps
from sqlalchemy.exc import OperationalError

logger = logging.getLogger("resilience")


class DependencyUnavailableError(Exception):
    """Кидається після вичерпання всіх спроб retry — сигнал для fallback."""
    pass


def retry_with_backoff(max_attempts=3, base_delay_seconds=0.3, backoff_factor=2,
                        exceptions=(OperationalError,)):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            attempt = 0
            delay = base_delay_seconds
            last_exc = None

            while attempt < max_attempts:
                attempt += 1
                try:
                    result = fn(*args, **kwargs)
                    if attempt > 1:
                        logger.info(f"[RESILIENCE] Успіх після {attempt} спроб(и)")
                    return result
                except exceptions as e:
                    last_exc = e
                    logger.warning(
                        f"[RESILIENCE] Спроба {attempt}/{max_attempts} невдала: {e}"
                    )
                    if attempt < max_attempts:
                        time.sleep(delay)
                        delay *= backoff_factor

            logger.error(
                f"[RESILIENCE] Вичерпано {max_attempts} спроб. "
                f"Активується fallback. Остання помилка: {last_exc}"
            )
            raise DependencyUnavailableError(str(last_exc)) from last_exc

        return wrapper
    return decorator