"""
Consent Management Engine (GDPR Art. 7): згода як виконуваний механізм, а не прапорець.

Модель даних
  user_consents        поточний стан згоди ОКРЕМО для кожної мети (user_id + purpose унікальні):
                       is_granted, policy_version, granted_at, withdrawn_at, updated_at, source
  user_consent_events  append-only ІСТОРІЯ: кожна дія GRANT/REVOKE з версією політики,
                       каналом (source), часом і correlation ID - доказ того, що, коли і як прийнято
  outbox_messages      наслідки залежних дій (імітація черги розсилки / запису аналітики)

API (лише сам суб'єкт; тіло application/json, щоб міжсайтова форма не могла дати чужу згоду)
  GET  /api/users/<id>/consents
  POST /api/users/<id>/consents/<PURPOSE>/grant    {"policy_version": "...", "source": "web"}
  POST /api/users/<id>/consents/<PURPOSE>/revoke   {"source": "web"}
Залежні дії (проходять через ConsentPolicyGate безпосередньо перед виконанням):
  POST /api/users/<id>/marketing-email   (operator/administrator)  мета MARKETING_EMAIL
  POST /api/users/<id>/analytics-event   (сам користувач)          мета OPTIONAL_ANALYTICS

Policy Gate кожного разу читає АКТУАЛЬНИЙ стан із БД (без кешу), тому відкликання діє негайно.
Фонова відправка (dispatch_pending_messages) перевіряє згоду ще раз перед виконанням.
Системні й договірні функції (вхід, експорт, анонімізація) Gate не викликають.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.exc import IntegrityError

from models import User, db
from privacy.export import (
    DENY_BODY_FORBIDDEN, DENY_BODY_NOT_FOUND, DENY_BODY_UNAUTHORIZED, _iso_utc, authorize_export,
)
from privacy.secure_logging import current_correlation_id, log_security_event

logger = logging.getLogger(__name__)

MARKETING_EMAIL = "MARKETING_EMAIL"
OPTIONAL_ANALYTICS = "OPTIONAL_ANALYTICS"
PURPOSES = (MARKETING_EMAIL, OPTIONAL_ANALYTICS)

# Актуальна версія політики для кожної мети. Підвищення версії робить старі згоди недійсними.
CURRENT_POLICY_VERSION = {MARKETING_EMAIL: "2026-10-01", OPTIONAL_ANALYTICS: "2026-10-01"}

ALLOWED_SOURCES = frozenset({"web", "api", "mobile"})
DEFAULT_SOURCE = "api"
INTERNAL_SOURCE_ERASURE = "erasure"
STAFF_ROLES = frozenset({"operator", "administrator"})


# ---------------------------------------------------------------------------
# Модель даних
# ---------------------------------------------------------------------------

class UserConsent(db.Model):
    __tablename__ = "user_consents"
    __table_args__ = (db.UniqueConstraint("user_id", "purpose", name="uq_user_consent_purpose"),)

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    purpose = db.Column(db.String(50), nullable=False)
    is_granted = db.Column(db.Boolean, nullable=False, default=False)
    policy_version = db.Column(db.String(20), nullable=False)
    granted_at = db.Column(db.DateTime, nullable=True)
    withdrawn_at = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    source = db.Column(db.String(20), nullable=False)


class ConsentEvent(db.Model):
    __tablename__ = "user_consent_events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    purpose = db.Column(db.String(50), nullable=False)
    action = db.Column(db.String(10), nullable=False)          # GRANT | REVOKE
    policy_version = db.Column(db.String(20), nullable=False)
    source = db.Column(db.String(20), nullable=False)
    correlation_id = db.Column(db.String(64), nullable=True)
    occurred_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class OutboxMessage(db.Model):
    __tablename__ = "outbox_messages"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    purpose = db.Column(db.String(50), nullable=False)
    action = db.Column(db.String(30), nullable=False)          # marketing_email | analytics_event
    status = db.Column(db.String(20), nullable=False)          # queued | sent | blocked | recorded
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime, nullable=True)


# ---------------------------------------------------------------------------
# Помилки
# ---------------------------------------------------------------------------

class UnknownPurpose(ValueError):
    pass


class InvalidSource(ValueError):
    pass


class PolicyVersionMismatch(Exception):
    def __init__(self, current: str):
        super().__init__(current)
        self.current = current


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str          # granted | no_consent | withdrawn | policy_version_outdated | unknown_purpose
    purpose: str


class ConsentDenied(Exception):
    def __init__(self, decision: Decision):
        super().__init__(decision.reason)
        self.decision = decision


# ---------------------------------------------------------------------------
# Policy Gate
# ---------------------------------------------------------------------------

class ConsentPolicyGate:
    """Єдине місце, де вирішується, чи дозволена залежна дія. Без кешу: завжди актуальний стан БД."""

    def check(self, user_id: int, purpose: str, lock: bool = False) -> Decision:
        if purpose not in CURRENT_POLICY_VERSION:
            return Decision(False, "unknown_purpose", str(purpose))
        query = UserConsent.query.filter_by(user_id=user_id, purpose=purpose).populate_existing()
        if lock:                                  # рішення й дія атомарні відносно одночасного REVOKE
            query = query.with_for_update()
        row = query.first()
        if row is None:
            return Decision(False, "no_consent", purpose)
        if not row.is_granted:
            return Decision(False, "withdrawn", purpose)
        if row.policy_version != CURRENT_POLICY_VERSION[purpose]:
            return Decision(False, "policy_version_outdated", purpose)
        return Decision(True, "granted", purpose)

    def require(self, user_id: int, purpose: str, lock: bool = False) -> Decision:
        decision = self.check(user_id, purpose, lock=lock)
        if not decision.allowed:
            raise ConsentDenied(decision)
        return decision


GATE = ConsentPolicyGate()


# ---------------------------------------------------------------------------
# Команди GRANT / REVOKE (сервісний шар)
# ---------------------------------------------------------------------------

def _validate(purpose: str, source: str) -> None:
    if purpose not in CURRENT_POLICY_VERSION:
        raise UnknownPurpose(purpose)
    if source not in ALLOWED_SOURCES and source != INTERNAL_SOURCE_ERASURE:
        raise InvalidSource(source)


def _locked_row(user_id: int, purpose: str) -> Optional[UserConsent]:
    return (UserConsent.query.filter_by(user_id=user_id, purpose=purpose)
            .populate_existing().with_for_update().first())


def serialize_consent(row: UserConsent) -> dict:
    return {
        "purpose": row.purpose,
        "is_granted": bool(row.is_granted),
        "policy_version": row.policy_version,
        "granted_at": _iso_utc(row.granted_at),
        "withdrawn_at": _iso_utc(row.withdrawn_at),
        "updated_at": _iso_utc(row.updated_at),
        "source": row.source,
    }


def grant_consent(user_id: int, purpose: str, policy_version: Optional[str] = None,
                  source: str = DEFAULT_SOURCE, correlation_id: Optional[str] = None,
                  _retry: bool = True) -> dict:
    _validate(purpose, source)
    current = CURRENT_POLICY_VERSION[purpose]
    version = policy_version or current
    if version != current:
        raise PolicyVersionMismatch(current)
    correlation_id = correlation_id or current_correlation_id()
    now = datetime.utcnow()

    row = _locked_row(user_id, purpose)
    if row is None:
        row = UserConsent(user_id=user_id, purpose=purpose, is_granted=True, policy_version=version,
                          granted_at=now, withdrawn_at=None, updated_at=now, source=source)
        db.session.add(row)
        status = "granted"
    elif row.is_granted and row.policy_version == version:
        return {"status": "already_granted", "consent": serialize_consent(row)}    # ідемпотентно
    else:
        status = "renewed" if row.is_granted else "granted"
        row.is_granted, row.policy_version = True, version
        row.granted_at, row.withdrawn_at = now, None
        row.updated_at, row.source = now, source

    db.session.add(ConsentEvent(user_id=user_id, purpose=purpose, action="GRANT",
                                policy_version=version, source=source,
                                correlation_id=correlation_id, occurred_at=now))
    try:
        db.session.commit()
    except IntegrityError:                    # гонка при першому створенні запису
        db.session.rollback()
        if _retry:
            return grant_consent(user_id, purpose, policy_version, source, correlation_id, _retry=False)
        raise
    return {"status": status, "consent": serialize_consent(row)}


def _withdraw_row(row: UserConsent, source: str, correlation_id: Optional[str], now: datetime) -> None:
    row.is_granted = False
    row.withdrawn_at = now
    row.updated_at = now
    row.source = source
    db.session.add(ConsentEvent(user_id=row.user_id, purpose=row.purpose, action="REVOKE",
                                policy_version=row.policy_version, source=source,
                                correlation_id=correlation_id, occurred_at=now))


def revoke_consent(user_id: int, purpose: str, source: str = DEFAULT_SOURCE,
                   correlation_id: Optional[str] = None) -> dict:
    _validate(purpose, source)
    correlation_id = correlation_id or current_correlation_id()
    row = _locked_row(user_id, purpose)
    if row is None:
        return {"status": "no_consent", "consent": None}               # нічого не створюємо
    if not row.is_granted:
        return {"status": "already_revoked", "consent": serialize_consent(row)}   # без нових записів
    _withdraw_row(row, source, correlation_id, datetime.utcnow())
    db.session.commit()
    return {"status": "revoked", "consent": serialize_consent(row)}


def revoke_all_consents(user_id: int, source: str, correlation_id: Optional[str] = None) -> int:
    """Відкликає всі активні згоди БЕЗ commit (викликається всередині транзакції анонімізації)."""
    now = datetime.utcnow()
    rows = (UserConsent.query.filter_by(user_id=user_id, is_granted=True)
            .populate_existing().with_for_update().all())
    for row in rows:
        _withdraw_row(row, source, correlation_id, now)
    return len(rows)


def export_consents(user_id: int) -> dict:
    current = (UserConsent.query.filter_by(user_id=user_id)
               .order_by(UserConsent.purpose).all())
    history = (ConsentEvent.query.filter_by(user_id=user_id)
               .order_by(ConsentEvent.occurred_at, ConsentEvent.id).all())
    return {
        "current": [serialize_consent(r) for r in current],
        "history": [{
            "purpose": e.purpose, "action": e.action, "policy_version": e.policy_version,
            "source": e.source, "occurred_at": _iso_utc(e.occurred_at),
        } for e in history],
    }


# ---------------------------------------------------------------------------
# Залежні дії: кожна викликає Gate безпосередньо перед побічним ефектом
# ---------------------------------------------------------------------------

def queue_marketing_email(user_id: int) -> OutboxMessage:
    try:
        GATE.require(user_id, MARKETING_EMAIL, lock=True)
    except ConsentDenied:
        db.session.rollback()                  # знімає блокування; побічних ефектів немає
        raise
    message = OutboxMessage(user_id=user_id, purpose=MARKETING_EMAIL,
                            action="marketing_email", status="queued")
    db.session.add(message)
    db.session.commit()
    return message


def record_analytics_event(user_id: int) -> OutboxMessage:
    try:
        GATE.require(user_id, OPTIONAL_ANALYTICS, lock=True)
    except ConsentDenied:
        db.session.rollback()
        raise
    event = OutboxMessage(user_id=user_id, purpose=OPTIONAL_ANALYTICS, action="analytics_event",
                          status="recorded", processed_at=datetime.utcnow())
    db.session.add(event)
    db.session.commit()
    return event


def dispatch_pending_messages() -> dict:
    """
    Фоновий worker: ПЕРЕД відправкою кожного повідомлення згода перевіряється ще раз.
    Якщо її відкликано після постановки в чергу, повідомлення блокується, а не відправляється.
    """
    counts = {"sent": 0, "blocked": 0}
    pending = (OutboxMessage.query.filter_by(action="marketing_email", status="queued")
               .order_by(OutboxMessage.id).all())
    for message in pending:
        decision = GATE.check(message.user_id, message.purpose, lock=True)
        message.status = "sent" if decision.allowed else "blocked"   # "sent": імітація, SMTP немає
        message.processed_at = datetime.utcnow()
        counts["sent" if decision.allowed else "blocked"] += 1
        db.session.commit()
    return counts


# ---------------------------------------------------------------------------
# HTTP-шар
# ---------------------------------------------------------------------------

def _actor_id(principal: Any) -> Optional[int]:
    return getattr(principal, "id", None) if getattr(principal, "is_authenticated", False) else None


def _auth_error(decision: str, event: str, principal: Any, subject_id: int):
    if decision == "unauthenticated":
        log_security_event(event, "denied", reason="unauthenticated")
        return DENY_BODY_UNAUTHORIZED, 401
    log_security_event(event, "denied", actor_id=_actor_id(principal), subject_id=subject_id,
                       reason="not_subject")
    return DENY_BODY_FORBIDDEN, 403


def handle_consent_command(principal: Any, subject_id: int, purpose: str, action: str, payload: Any):
    """action: 'grant' | 'revoke'. Лише сам суб'єкт: жодна роль не може дати згоду за іншого."""
    event = f"consent_{action}"
    decision = authorize_export(principal, subject_id, privileged_roles=frozenset())
    if decision != "allow":
        return _auth_error(decision, event, principal, subject_id)
    if not isinstance(payload, dict):
        return {"error": "json_body_required"}, 400
    if purpose not in CURRENT_POLICY_VERSION:
        return {"error": "unknown_purpose"}, 400
    source = payload.get("source", DEFAULT_SOURCE)
    if source not in ALLOWED_SOURCES:
        return {"error": "invalid_source"}, 400
    version = payload.get("policy_version")
    if version is not None and not isinstance(version, str):
        return {"error": "invalid_policy_version"}, 400

    actor = _actor_id(principal)
    try:
        if action == "grant":
            result = grant_consent(subject_id, purpose, version, source)
        else:
            result = revoke_consent(subject_id, purpose, source)
    except PolicyVersionMismatch as exc:
        log_security_event(event, "denied", actor_id=actor, subject_id=subject_id,
                           reason="policy_version_outdated")
        return {"error": "policy_version_outdated", "current_policy_version": exc.current}, 409
    except Exception:
        db.session.rollback()
        logger.error("consent command failed", exc_info=True)
        return {"error": "consent_command_failed"}, 500

    changed = result["status"] in ("granted", "renewed", "revoked")
    log_security_event(event, "success" if changed else "noop", actor_id=actor,
                       subject_id=subject_id, reason=purpose)
    return {"status": result["status"], "purpose": purpose, "consent": result["consent"]}, 200


def handle_consents_list(principal: Any, subject_id: int):
    decision = authorize_export(principal, subject_id)
    if decision != "allow":
        return _auth_error(decision, "consent_list", principal, subject_id)
    if db.session.get(User, subject_id) is None:
        return DENY_BODY_NOT_FOUND, 404
    body = {"subject_id": subject_id, "current_policy_versions": dict(CURRENT_POLICY_VERSION)}
    body.update(export_consents(subject_id))
    return body, 200


def _consent_required(user_id: int, exc: ConsentDenied, actor: Optional[int], event: str):
    log_security_event(event, "denied", actor_id=actor, subject_id=user_id, reason=exc.decision.reason)
    return {"error": "consent_required", "purpose": exc.decision.purpose,
            "reason": exc.decision.reason}, 403


def handle_marketing_email(principal: Any, subject_id: int):
    if not getattr(principal, "is_authenticated", False):
        log_security_event("marketing_email", "denied", reason="unauthenticated")
        return DENY_BODY_UNAUTHORIZED, 401
    actor = _actor_id(principal)
    if getattr(principal, "role", None) not in STAFF_ROLES:
        log_security_event("marketing_email", "denied", actor_id=actor, subject_id=subject_id,
                           reason="not_staff")
        return DENY_BODY_FORBIDDEN, 403
    if db.session.get(User, subject_id) is None:
        return DENY_BODY_NOT_FOUND, 404
    try:
        message = queue_marketing_email(subject_id)
    except ConsentDenied as exc:
        return _consent_required(subject_id, exc, actor, "marketing_email")
    log_security_event("marketing_email", "success", actor_id=actor, subject_id=subject_id)
    return {"status": "queued", "message_id": message.id, "purpose": MARKETING_EMAIL}, 200


def handle_analytics_event(principal: Any, subject_id: int):
    decision = authorize_export(principal, subject_id, privileged_roles=frozenset())
    if decision != "allow":
        return _auth_error(decision, "analytics_event", principal, subject_id)
    actor = _actor_id(principal)
    try:
        event = record_analytics_event(subject_id)
    except ConsentDenied as exc:
        return _consent_required(subject_id, exc, actor, "analytics_event")
    log_security_event("analytics_event", "success", actor_id=actor, subject_id=subject_id)
    return {"status": "recorded", "event_id": event.id, "purpose": OPTIONAL_ANALYTICS}, 200


def _respond(body: dict, status: int):
    from flask import jsonify

    response = jsonify(body)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    return response


def consent_command_response(principal: Any, subject_id: int, purpose: str, action: str):
    from flask import request

    return _respond(*handle_consent_command(principal, subject_id, purpose, action,
                                            request.get_json(silent=True)))


def consents_list_response(principal: Any, subject_id: int):
    return _respond(*handle_consents_list(principal, subject_id))


def marketing_email_response(principal: Any, subject_id: int):
    return _respond(*handle_marketing_email(principal, subject_id))


def analytics_event_response(principal: Any, subject_id: int):
    return _respond(*handle_analytics_event(principal, subject_id))
