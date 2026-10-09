"""
Right of Access (GDPR Art. 15): Personal Data Export.

Ендпоінт:  GET /api/users/<id>/personal-data

Контракт відповіді (schema_version 1.0), ключі в стабільному порядку:

  schema_version        версія схеми (старі експорти не стають неоднозначними)
  metadata              generated_at (UTC, ISO 8601), time_zone, correlation_id, format,
                        categories, omitted_fields (documented omission), warnings
  subject               {id}
  profile               users                          -> дані облікового запису
  settings              (немає джерела)                -> documented omission
  activity_history      users.api_history + history/user_<id>.json (без дублів)
  registration_requests user_requests (за email суб'єкта)
  consents              user_consents + user_consent_events -> поточний стан і історія змін

Кожна секція має однакову форму: {source, time_zone, available, data, [note]}.

Контроль доступу: порівнюється authenticated principal із subject ID.
Дозволено лише самому користувачеві та ролям зі списку EXPORT_PRIVILEGED_ROLES.
Для всіх інших відповідь однакова (403, без тіла з даними) незалежно від того,
існує запитаний профіль чи ні: факт існування чужого профілю не розкривається.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import func

from privacy.secure_logging import current_correlation_id, log_security_event

SCHEMA_VERSION = "1.0"
CATEGORIES = ("profile", "settings", "activity_history", "registration_requests", "consents")

# Ролі, яким явно дозволено експортувати дані ІНШИХ користувачів.
EXPORT_PRIVILEGED_ROLES = frozenset({"administrator"})

# Мінімізація: ці поля навмисно НЕ потрапляють в експорт (documented omission).
OMITTED_FIELDS = (
    "users.password_hash",
    "user_requests.password_hash",
    "users.role",
    "users.is_active_flag",
    "user_requests.reviewed_by",
    "data of other users (e.g. requests reviewed by this user)",
)

DENY_BODY_FORBIDDEN = {"error": "forbidden"}
DENY_BODY_UNAUTHORIZED = {"error": "unauthorized"}
DENY_BODY_NOT_FOUND = {"error": "not_found"}


# ---------------------------------------------------------------------------
# Авторизація
# ---------------------------------------------------------------------------

def authorize_export(principal: Any, subject_id: int,
                     privileged_roles=EXPORT_PRIVILEGED_ROLES) -> str:
    """Повертає 'allow' | 'unauthenticated' | 'forbidden'. Не залежить лише від path parameter."""
    if principal is None or not getattr(principal, "is_authenticated", False):
        return "unauthenticated"
    if getattr(principal, "is_active_flag", True) is False:
        return "forbidden"
    if getattr(principal, "id", None) == subject_id:
        return "allow"
    if getattr(principal, "role", None) in privileged_roles:
        return "allow"
    return "forbidden"


# ---------------------------------------------------------------------------
# Збір даних
# ---------------------------------------------------------------------------

def _iso_utc(value: Optional[datetime]) -> Optional[str]:
    """Дати в БД зберігаються як naive UTC (datetime.utcnow); робимо часову зону явною."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _section(source: Any, time_zone: Optional[str], available: bool, data: Any,
             note: Optional[str] = None) -> dict:
    section = {"source": source, "time_zone": time_zone, "available": available, "data": data}
    if note:
        section["note"] = note
    return section


def _collect_profile(user) -> dict:
    return _section("users", "UTC", True, {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "created_at": _iso_utc(user.created_at),
    })


def _collect_settings() -> dict:
    return _section(None, None, False, {},
                    note="The system stores no user-configurable settings.")


def _collect_activity(user, warnings: list) -> dict:
    from history_utils import load_history

    entries, seen = [], set()

    def add(raw: Any, origin: str) -> None:
        if not isinstance(raw, dict):
            return
        item = {
            "api": raw.get("api"),
            "params": raw.get("params"),
            "result": raw.get("result"),
            "timestamp": raw.get("timestamp"),
        }
        key = (item["api"], item["params"], item["result"], item["timestamp"])
        if key in seen:                      # без дублювання між двома сховищами
            return
        seen.add(key)
        item["origin"] = origin
        entries.append(item)

    for raw in (user.api_history or []):
        add(raw, "users.api_history")
    try:
        for raw in load_history(user.id):
            add(raw, f"history/user_{user.id}.json")
    except Exception:                        # пошкоджений файл не повинен мовчки зникати
        warnings.append(f"history/user_{user.id}.json is unreadable; activity may be incomplete")

    entries.sort(key=lambda e: (str(e["timestamp"]), str(e["api"])))
    return _section(["users.api_history", f"history/user_{user.id}.json"],
                    "server-local", True, entries,
                    note="Timestamps of activity entries are recorded in server local time.")


def _collect_registration_requests(user) -> dict:
    from models import UserRequest

    rows = (UserRequest.query
            .filter(func.lower(UserRequest.email) == (user.email or "").lower())
            .order_by(UserRequest.request_date, UserRequest.id).all())
    data = [{
        "id": r.id,
        "full_name": r.full_name,
        "email": r.email,
        "phone": r.phone,
        "status": r.status,
        "requested_at": _iso_utc(r.request_date),
        "reviewed_at": _iso_utc(r.reviewed_at),
    } for r in rows]
    return _section("user_requests", "UTC", True, data)


def _collect_consents(user) -> dict:
    from privacy.consent import export_consents

    return _section(["user_consents", "user_consent_events"], "UTC", True, export_consents(user.id),
                    note="current = actual state per purpose; history = every GRANT/REVOKE event.")


def build_personal_data_export(user, correlation_id: Optional[str] = None,
                               now: Optional[datetime] = None) -> dict:
    """Збирає повний експорт одного користувача. Дані інших користувачів не змішуються."""
    now = now or datetime.now(timezone.utc)
    warnings: list = []
    profile = _collect_profile(user)
    settings = _collect_settings()
    activity = _collect_activity(user, warnings)
    requests_ = _collect_registration_requests(user)
    consents = _collect_consents(user)
    return {
        "schema_version": SCHEMA_VERSION,
        "metadata": {
            "generated_at": now.astimezone(timezone.utc).isoformat(),
            "time_zone": "UTC",
            "correlation_id": correlation_id or current_correlation_id(),
            "format": "application/json",
            "categories": list(CATEGORIES),
            "omitted_fields": list(OMITTED_FIELDS),
            "warnings": warnings,
        },
        "subject": {"id": user.id},
        "profile": profile,
        "settings": settings,
        "activity_history": activity,
        "registration_requests": requests_,
        "consents": consents,
    }


# ---------------------------------------------------------------------------
# Обробник запиту
# ---------------------------------------------------------------------------

def handle_export_request(principal: Any, subject_id: int):
    """Повертає (тіло, HTTP-статус). У журнал потрапляють лише ID, результат і причина."""
    from models import User

    actor_id = getattr(principal, "id", None) if getattr(principal, "is_authenticated", False) else None
    decision = authorize_export(principal, subject_id)

    if decision == "unauthenticated":
        log_security_event("personal_data_export", "denied", reason="unauthenticated")
        return DENY_BODY_UNAUTHORIZED, 401
    if decision == "forbidden":
        log_security_event("personal_data_export", "denied", actor_id=actor_id,
                           subject_id=subject_id, reason="not_subject_or_privileged")
        return DENY_BODY_FORBIDDEN, 403

    user = User.query.get(subject_id)
    if user is None:                         # сюди потрапляє лише привілейована роль
        log_security_event("personal_data_export", "failure", actor_id=actor_id,
                           subject_id=subject_id, reason="subject_not_found")
        return DENY_BODY_NOT_FOUND, 404

    payload = build_personal_data_export(user)
    log_security_event("personal_data_export", "success", actor_id=actor_id, subject_id=user.id)
    return payload, 200


def personal_data_response(principal: Any, subject_id: int):
    """Flask-відповідь: JSON + заборона кешування (відповідь містить персональні дані)."""
    from flask import jsonify

    body, status = handle_export_request(principal, subject_id)
    response = jsonify(body)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    return response
