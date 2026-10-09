"""
Privacy-safe audit log: факт операції без копіювання персональних даних.

Таблиця privacy_audit_events зберігає лише: тип події, ID суб'єкта й actor-а,
результат, correlation ID, час і ЛІЧИЛЬНИКИ в details. Видалені значення (ім'я,
email, телефон) сюди не потрапляють, тому audit не стає прихованим сховищем PII.

Таблицю створює db.create_all() (вона нова, ALTER TABLE не потрібен).
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from models import db

logger = logging.getLogger(__name__)


class PrivacyAuditEvent(db.Model):
    __tablename__ = "privacy_audit_events"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False)
    subject_id = db.Column(db.Integer, nullable=True)
    actor_id = db.Column(db.Integer, nullable=True)
    outcome = db.Column(db.String(20), nullable=False)
    correlation_id = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    details = db.Column(db.JSON, default=dict)

    def __repr__(self):
        return f"<PrivacyAuditEvent {self.event_type} {self.outcome} subject={self.subject_id}>"


def record_audit_event(event_type: str, outcome: str, subject_id: Optional[int],
                       actor_id: Optional[int], correlation_id: Optional[str],
                       details: Optional[dict] = None) -> None:
    """Записує подію в ОКРЕМІЙ транзакції. Збій аудиту не маскує основну помилку."""
    safe_details = {k: v for k, v in (details or {}).items() if isinstance(v, (int, bool))}
    try:
        db.session.add(PrivacyAuditEvent(
            event_type=event_type, outcome=outcome, subject_id=subject_id,
            actor_id=actor_id, correlation_id=correlation_id, details=safe_details))
        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.error("privacy audit event could not be stored", exc_info=True)
