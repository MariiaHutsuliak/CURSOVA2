"""
Right to Erasure (GDPR Art. 17): workflow незворотної анонімізації користувача.

Ендпоінт:  POST /api/users/<id>/anonymize     тіло: {"confirm": true}  (application/json)

Політика обробки сутностей (ERASURE_POLICY):

  DELETE     - дані видаляються повністю
  ANONYMIZE  - запис лишається, PII замінено випадковими значеннями без зв'язку з оригіналом
  RETAIN     - запис лишається без змін (змодельоване правило зберігання)
  SKIP       - не стосується суб'єкта

Властивості workflow:
  * Авторизація: сам користувач або роль із ERASURE_PRIVILEGED_ROLES; тільки POST.
  * Захист від випадкового/міжсайтового виклику: потрібне тіло application/json з confirm=true
    (форма з іншого сайту не може надіслати такий запит без CORS preflight).
  * Атомарність: усі зміни БД - в одній транзакції; файл історії видаляється ПІСЛЯ commit.
  * Ідемпотентність: повторний запит нічого не відновлює і не створює; повторно дочищає залишки.
  * Анонімізація, а не псевдонімізація: нові значення випадкові (secrets.token_hex), таблиця
    відповідності не зберігається, відновити початкові дані неможливо.
  * Audit: privacy_audit_events + security-подія в журналі, без видалених значень.
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import func

from privacy.audit import record_audit_event
from privacy.consent import INTERNAL_SOURCE_ERASURE, revoke_all_consents
from privacy.export import (
    DENY_BODY_FORBIDDEN, DENY_BODY_NOT_FOUND, DENY_BODY_UNAUTHORIZED, authorize_export,
)
from privacy.secure_logging import current_correlation_id, log_security_event

logger = logging.getLogger(__name__)

ANON_DOMAIN = "anon.local"
ANON_USERNAME_PREFIX = "anon-"
ANON_FULL_NAME = "Anonymized"
# Значення, яке не є валідним хешем: check_password_hash для нього завжди False.
UNUSABLE_PASSWORD_HASH = "!anonymized"

ERASURE_PRIVILEGED_ROLES = frozenset({"administrator"})

EVENT_TYPE = "USER_ANONYMIZED"

ERASURE_POLICY = (
    # (сутність / поля, дія, обґрунтування)
    ("users.username, users.email, users.password_hash", "ANONYMIZE",
     "прямі ідентифікатори; замінюються унікальними випадковими значеннями (unique constraint збережено)"),
    ("users.api_history", "DELETE",
     "історія запитів може містити PII в параметрах"),
    ("history/user_<id>.json", "DELETE",
     "резервне сховище тієї самої історії; видаляється після commit"),
    ("users.id, users.role, users.created_at", "RETAIN",
     "технічні поля без PII; id потрібен для цілісності зовнішніх ключів"),
    ("user_requests (ПІБ, email, телефон, password_hash суб'єкта)", "ANONYMIZE",
     "рядок лишається як запис про рішення щодо реєстрації, PII прибрано"),
    ("user_requests (status, request_date, reviewed_at, reviewed_by)", "RETAIN",
     "змодельоване правило зберігання: журнал рішень адміністратора без PII"),
    ("user_requests, розглянуті суб'єктом (reviewed_by = id)", "RETAIN",
     "дані інших людей; зв'язок reviewed_by тепер веде на анонімізований акаунт"),
    ("user_consents, user_consent_events", "RETAIN",
     "доказ згод і відкликань; містять лише user_id, мету, версію політики й час, без PII; "
     "усі активні згоди відкликаються у тій самій транзакції"),
    ("outbox_messages", "RETAIN",
     "журнал виконаних залежних дій; містить лише user_id, мету й статус, без PII"),
    ("privacy_audit_events", "RETAIN",
     "містить лише ID, результат, час і лічильники, без PII"),
    ("employees, suppliers, contracts, sales та ін.", "SKIP",
     "не пов'язані з обліковим записом користувача; окремі суб'єкти даних"),
)


class SubjectNotFound(Exception):
    pass


# ---------------------------------------------------------------------------
# Кроки workflow (окремі функції, щоб кожен можна було перевірити й зламати в тесті)
# ---------------------------------------------------------------------------

def _is_anonymized(user) -> bool:
    return (str(user.email).endswith("@" + ANON_DOMAIN)
            and str(user.username).startswith(ANON_USERNAME_PREFIX)
            and not user.is_active_flag)


def _anonymize_user_row(user) -> None:
    token = secrets.token_hex(8)       # випадково: не похідне від початкових даних
    user.username = f"{ANON_USERNAME_PREFIX}{token}"
    user.email = f"deleted-{token}@{ANON_DOMAIN}"
    user.password_hash = UNUSABLE_PASSWORD_HASH
    user.is_active_flag = False


def _anonymize_requests(original_email: str) -> int:
    from models import UserRequest

    rows = UserRequest.query.filter(func.lower(UserRequest.email) == original_email.lower()).all()
    for row in rows:
        row.full_name = ANON_FULL_NAME
        row.email = f"deleted-{secrets.token_hex(8)}@{ANON_DOMAIN}"
        row.phone = None
        row.password_hash = UNUSABLE_PASSWORD_HASH
    return len(rows)


def _delete_history_file(user_id: int) -> bool:
    from history_utils import history_file

    path = history_file(user_id)
    existed = path.exists()
    path.unlink(missing_ok=True)
    return existed


def anonymize_user(subject_id: int, actor_id: Optional[int],
                   correlation_id: Optional[str] = None) -> dict:
    """
    Виконує workflow. Повертає {"status": "anonymized"|"already_anonymized", "summary": {...}}.
    Піднімає SubjectNotFound; у разі збою відкочує транзакцію і піднімає початкову помилку.
    """
    from models import User, db

    correlation_id = correlation_id or current_correlation_id()
    user = User.query.filter_by(id=subject_id).with_for_update().first()   # блокування рядка
    if user is None:
        raise SubjectNotFound(subject_id)

    already = _is_anonymized(user)
    summary = {"users_anonymized": 0, "user_requests_anonymized": 0, "consents_withdrawn": 0,
               "activity_history_cleared": True, "history_file_deleted": False}
    try:
        if not already:
            original_email = user.email                      # лише в пам'яті, нікуди не пишеться
            _anonymize_user_row(user)
            summary["users_anonymized"] = 1
            summary["user_requests_anonymized"] = _anonymize_requests(original_email)
        user.api_history = []
        # Згоди відкликаються в тій самій транзакції; записи історії лишаються як доказ (без PII).
        summary["consents_withdrawn"] = revoke_all_consents(subject_id, INTERNAL_SOURCE_ERASURE,
                                                            correlation_id)
        db.session.commit()                                  # єдина межа транзакції
    except Exception:
        db.session.rollback()
        record_audit_event(EVENT_TYPE, "failure", subject_id, actor_id, correlation_id)
        log_security_event("anonymize_user", "failure", actor_id=actor_id,
                           subject_id=subject_id, reason="rolled_back")
        raise

    # Файл не транзакційний: видаляємо після commit. Збій тут безпечний, бо повторний
    # запит дочищає файл (workflow ідемпотентний).
    summary["history_file_deleted"] = _delete_history_file(subject_id)

    status = "already_anonymized" if already else "anonymized"
    record_audit_event(EVENT_TYPE, "success" if not already else "noop",
                       subject_id, actor_id, correlation_id, summary)
    log_security_event("anonymize_user", "success" if not already else "noop",
                       actor_id=actor_id, subject_id=subject_id)
    return {"status": status, "summary": summary}


# ---------------------------------------------------------------------------
# HTTP-обробник
# ---------------------------------------------------------------------------

def handle_anonymize_request(principal: Any, subject_id: int, payload: Any):
    """Повертає (тіло, HTTP-статус)."""
    actor_id = getattr(principal, "id", None) if getattr(principal, "is_authenticated", False) else None
    decision = authorize_export(principal, subject_id, ERASURE_PRIVILEGED_ROLES)

    if decision == "unauthenticated":
        log_security_event("anonymize_user", "denied", reason="unauthenticated")
        return DENY_BODY_UNAUTHORIZED, 401
    if decision == "forbidden":
        log_security_event("anonymize_user", "denied", actor_id=actor_id,
                           subject_id=subject_id, reason="not_subject_or_privileged")
        return DENY_BODY_FORBIDDEN, 403

    if not (isinstance(payload, dict) and payload.get("confirm") is True):
        log_security_event("anonymize_user", "denied", actor_id=actor_id,
                           subject_id=subject_id, reason="confirmation_required")
        return {"error": "confirmation_required"}, 400

    correlation_id = current_correlation_id()
    try:
        result = anonymize_user(subject_id, actor_id, correlation_id)
    except SubjectNotFound:
        log_security_event("anonymize_user", "failure", actor_id=actor_id,
                           subject_id=subject_id, reason="subject_not_found")
        return DENY_BODY_NOT_FOUND, 404
    except Exception:
        logger.error("anonymization failed and was rolled back", exc_info=True)
        return {"error": "erasure_failed", "correlation_id": correlation_id}, 500

    return {
        "status": result["status"],
        "subject_id": subject_id,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "correlation_id": correlation_id,
        "summary": result["summary"],
    }, 200


def anonymize_response(principal: Any, subject_id: int):
    """Flask-відповідь. Якщо користувач анонімізував себе, його сесію завершено."""
    from flask import jsonify, request
    from flask_login import logout_user

    body, status = handle_anonymize_request(principal, subject_id, request.get_json(silent=True))
    if status == 200 and getattr(principal, "id", None) == subject_id:
        logout_user()
    response = jsonify(body)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    return response
