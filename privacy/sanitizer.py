"""
Централізована санітизація персональних даних (PII, Personally Identifiable
Information) і секретів для журналів застосунку.

Політика логування (Logging Policy):

  ALLOWED   - значення пишуться як є (діагностичні, не персональні поля).
  MASKED    - частково маскуються: лишається достатньо для діагностики,
              але початкове значення відновити неможливо.
  FORBIDDEN - повністю замінюються на [REDACTED].

Модуль не залежить від Flask і logging, тому його можна тестувати окремо
і використовувати де завгодно (форматувальник логів, експорт, аудит).
"""
from __future__ import annotations

import dataclasses
import re
from typing import Any

REDACTED = "[REDACTED]"

# ---------------------------------------------------------------------------
# Політика логування
# ---------------------------------------------------------------------------

# Дозволені поля: не є персональними, потрібні для діагностики.
ALLOWED_FIELDS = frozenset({
    "timestamp", "level", "logger", "message", "correlation_id", "operation",
    "outcome", "reason", "actor_id", "subject_id", "status", "method", "path",
    "duration_ms", "exception",
})

# Маскуються частково (ключ -> функція маскування).
# Визначено нижче, після самих функцій: MASKED_FIELDS.

# Заборонені до запису (повна заміна на [REDACTED]) - за підрядком у назві ключа.
FORBIDDEN_KEY_PARTS = (
    "password", "passwd", "pwd", "token", "secret", "api_key", "apikey",
    "api-key", "session_id", "sessionid", "cookie", "private_key",
    "authorization", "credential",
)


# ---------------------------------------------------------------------------
# Функції маскування окремих значень
# ---------------------------------------------------------------------------

def mask_email(value: str) -> str:
    """maria.test@example.com -> m***@example.com"""
    local, sep, domain = value.partition("@")
    if not sep or not local:
        return "***"
    return f"{local[0]}***@{domain}"


def mask_phone(value: str) -> str:
    """+380501234567 -> +*********567 (лишаються лише останні 3 цифри)."""
    if "*" in value:            # уже замасковано: повторний прохід не змінює значення
        return value
    digits = re.sub(r"\D", "", value)
    if len(digits) < 4:
        return "***"
    prefix = "+" if value.strip().startswith("+") else ""
    return f"{prefix}{'*' * (len(digits) - 3)}{digits[-3:]}"


def mask_name(value: str) -> str:
    """Maria Test -> M*** T***"""
    parts = [p for p in re.split(r"\s+", value.strip()) if p]
    if not parts:
        return "***"
    return " ".join(f"{p[0]}***" for p in parts)


# Ключі структурованих даних, значення яких маскуються (а не редагуються).
MASKED_FIELDS = {
    "email": mask_email,
    "e_mail": mask_email,
    "phone": mask_phone,
    "phone_number": mask_phone,
    "mobile": mask_phone,
    "full_name": mask_name,
    "username": mask_name,
    "first_name": mask_name,
    "last_name": mask_name,
}


def is_forbidden_key(key: Any) -> bool:
    k = str(key).lower()
    return any(part in k for part in FORBIDDEN_KEY_PARTS)


# ---------------------------------------------------------------------------
# Регулярні вирази для вільного тексту
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# Кандидат на телефон: цифри з пробілами/дужками/дефісами (без крапки, щоб не
# чіпати IP-адреси). Остаточне рішення приймає _phone_replacer.
_PHONE_RE = re.compile(r"(?<![\w*])\+?\d[\d\s()\-]{7,}\d(?!\w)")

_BEARER_RE = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=\-]{8,}", re.IGNORECASE)

# Токени за форматом (GitHub PAT, JWT, AWS access key id).
_TOKEN_FORMAT_RES = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)

# Облікові дані в URL: postgresql://user:pass@host -> postgresql://user:[REDACTED]@host
_URL_CREDS_RE = re.compile(r"(\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:)([^\s@/]+)(@)", re.IGNORECASE)

# key=value / key: value / "key": "value" / 'key': 'value' для заборонених ключів.
_SECRET_KV_RE = re.compile(
    r"""(?P<key>[A-Za-z0-9_\-]*(?:password|passwd|pwd|token|secret|api[_\-]?key|
        session[_\-]?id|cookie|private[_\-]?key|credential)[A-Za-z0-9_\-]*)
        (?P<sep>["']?\s*[:=]\s*)
        (?P<val>\[REDACTED\]|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;&}\])]+)""",
    re.IGNORECASE | re.VERBOSE,
)

# key=value для полів з іменем людини: значення маскується (M*** T***).
# Без лапок ім'я може складатися з 1-3 слів (кожне наступне з великої літери).
_NAME_KV_RE = re.compile(
    r"""(?P<key>\b(?:full_name|first_name|last_name|username)\b)
        (?P<sep>["']?\s*[:=]\s*)
        (?P<val>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'
            |[^\s,;&}\])'"]+(?:[ ]+(?-i:[A-ZА-ЯІЇЄҐ])[^\s,;&}\])'"]*){0,2})""",
    re.IGNORECASE | re.VERBOSE,
)

# Точні значення секретів застосунку (SECRET_KEY, пароль БД), які відомі на старті.
_KNOWN_SECRETS: set = set()
_MIN_KNOWN_SECRET_LEN = 6


def register_secret(value: Any) -> None:
    """Запам'ятовує точне значення секрету: далі воно редагується де б не з'явилось."""
    if isinstance(value, str) and len(value) >= _MIN_KNOWN_SECRET_LEN:
        _KNOWN_SECRETS.add(value)


def clear_registered_secrets() -> None:
    _KNOWN_SECRETS.clear()


def _phone_replacer(match: "re.Match") -> str:
    raw = match.group(0)
    digits = re.sub(r"\D", "", raw)
    if re.match(r"\d{4}-\d{2}-\d{2}", raw):  # дата, а не телефон
        return raw
    if not 9 <= len(digits) <= 15:
        return raw
    has_separators = bool(re.search(r"[\s()\-]", raw))
    if raw.startswith("+") or (len(digits) >= 10 and (digits.startswith("0") or has_separators)):
        return mask_phone(raw)
    return raw


def _secret_kv_replacer(match: "re.Match") -> str:
    val = match.group("val")
    if val.startswith(("'", '"')):
        quote = val[0]
        return f"{match.group('key')}{match.group('sep')}{quote}{REDACTED}{quote}"
    return f"{match.group('key')}{match.group('sep')}{REDACTED}"


def _name_kv_replacer(match: "re.Match") -> str:
    val = match.group("val")
    if val.startswith(("'", '"')):
        quote = val[0]
        return f"{match.group('key')}{match.group('sep')}{quote}{mask_name(val[1:-1])}{quote}"
    return f"{match.group('key')}{match.group('sep')}{mask_name(val)}"


# ---------------------------------------------------------------------------
# Публічний API
# ---------------------------------------------------------------------------

def sanitize_text(text: Any) -> str:
    """Санітизує довільний текст: повідомлення, JSON-рядок, текст exception."""
    if text is None:
        return ""
    s = text if isinstance(text, str) else str(text)

    # 1. Точні значення відомих секретів.
    for secret in _KNOWN_SECRETS:
        if secret in s:
            s = s.replace(secret, REDACTED)

    # 2. Секрети: токени за форматом, Bearer/Basic, облікові дані в URL, key=value.
    for rx in _TOKEN_FORMAT_RES:
        s = rx.sub(REDACTED, s)
    s = _BEARER_RE.sub(lambda m: f"{m.group(1)} {REDACTED}", s)
    s = _URL_CREDS_RE.sub(lambda m: f"{m.group(1)}{REDACTED}{m.group(3)}", s)
    s = _SECRET_KV_RE.sub(_secret_kv_replacer, s)

    # 3. PII: імена (за ключем), email і телефон маскуються частково.
    s = _NAME_KV_RE.sub(_name_kv_replacer, s)
    s = _EMAIL_RE.sub(lambda m: mask_email(m.group(0)), s)
    s = _PHONE_RE.sub(_phone_replacer, s)
    return s


def sanitize_value(key: Any, value: Any, _depth: int = 0) -> Any:
    """
    Санітизує значення структурованого поля з урахуванням його імені.
    Обробляє dict, list/tuple/set, dataclass, звичайні об'єкти (DTO) рекурсивно.
    """
    if _depth > 8:
        return REDACTED
    key_l = str(key).lower() if key is not None else ""

    if key_l and is_forbidden_key(key_l):
        return REDACTED
    if key_l in MASKED_FIELDS and isinstance(value, str):
        return MASKED_FIELDS[key_l](value)

    if isinstance(value, str):
        return sanitize_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, dict):
        return {k: sanitize_value(k, v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [sanitize_value(key, v, _depth + 1) for v in value]
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: sanitize_value(f.name, getattr(value, f.name, None), _depth + 1)
                for f in dataclasses.fields(value)}
    if hasattr(value, "__dict__") and not isinstance(value, type):
        public = {k: v for k, v in vars(value).items() if not k.startswith("_")}
        return {k: sanitize_value(k, v, _depth + 1) for k, v in public.items()}
    return sanitize_text(repr(value))
