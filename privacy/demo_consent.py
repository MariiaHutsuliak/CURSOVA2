"""
Live demo до Завдання 4 (Consent Management): GRANT -> ALLOW -> REVOKE -> DENY.

Запуск з кореня проєкту:   python -m privacy.demo_consent

Скрипт створює двох СИНТЕТИЧНИХ користувачів (суб'єкт і оператор розсилки), викликає ті самі
HTTP-ендпоінти, що й застосунок, друкує кожен крок із побічними ефектами і в кінці
прибирає всі свої записи. Реальних персональних даних тут немає.
"""
from __future__ import annotations

import json
import uuid

from app import app
from models import db, User
from privacy.audit import PrivacyAuditEvent
from privacy.consent import (
    ConsentEvent, OutboxMessage, UserConsent, dispatch_pending_messages,
)

MKT, ANA = "MARKETING_EMAIL", "OPTIONAL_ANALYTICS"


def _short(resp) -> str:
    body = resp.get_json()
    keep = {k: body[k] for k in ("status", "error", "purpose", "reason") if k in body}
    if body.get("consent"):
        c = body["consent"]
        keep["consent"] = {k: c[k] for k in ("is_granted", "policy_version", "source") if k in c}
    return f"{resp.status_code} {json.dumps(keep, ensure_ascii=False)}"


def _outbox(user_id: int) -> str:
    with app.app_context():
        rows = OutboxMessage.query.filter_by(user_id=user_id).all()
    stats = {}
    for r in rows:
        key = f"{r.action}/{r.status}"
        stats[key] = stats.get(key, 0) + 1
    return f"outbox_messages: {stats or 'порожньо'}"


def main() -> None:
    tag = uuid.uuid4().hex[:6]
    subject_pw, operator_pw = "DemoSubject-123", "DemoOperator-456"
    with app.app_context():
        db.create_all()
        subject = User(username=f"demo.subject.{tag}", email=f"demo.subject.{tag}@example.com",
                       role="authorized_user")
        subject.set_password(subject_pw)
        operator = User(username=f"demo.operator.{tag}", email=f"demo.operator.{tag}@example.com",
                        role="operator")
        operator.set_password(operator_pw)
        db.session.add_all([subject, operator])
        db.session.commit()
        sid, oid, sname, oname = subject.id, operator.id, subject.username, operator.username

    def login(name, pw):
        client = app.test_client()
        client.post("/login", data={"username": name, "password": pw})
        return client

    try:
        user, op = login(sname, subject_pw), login(oname, operator_pw)
        post_mkt = lambda: op.post(f"/api/users/{sid}/marketing-email")
        grant = lambda p, **b: user.post(f"/api/users/{sid}/consents/{p}/grant", json=b)
        revoke = lambda p, **b: user.post(f"/api/users/{sid}/consents/{p}/revoke", json=b)

        print(f"Суб'єкт id={sid}, оператор розсилки id={oid} (синтетичні)\n")
        print("[1] Початковий стан, згоди немає")
        print("    розсилка      ->", _short(post_mkt()))
        print("   ", _outbox(sid))

        print(f"\n[2] GRANT {MKT} (policy_version 2026-10-01, source web)")
        print("    GRANT         ->", _short(grant(MKT, policy_version="2026-10-01", source="web")))

        print("\n[3] ALLOW: залежна дія виконується")
        print("    розсилка      ->", _short(post_mkt()))
        print("   ", _outbox(sid))

        print(f"\n[4] REVOKE {MKT}")
        print("    REVOKE        ->", _short(revoke(MKT, source="web")))
        print("    REVOKE ще раз ->", _short(revoke(MKT, source="web")), "(ідемпотентно)")

        print("\n[5] DENY: та сама дія тепер заблокована, побічного ефекту немає")
        print("    розсилка      ->", _short(post_mkt()))
        print("   ", _outbox(sid), "(без змін)")

        print(f"\n[6] Ізоляція цілей: GRANT лише {ANA}")
        print("    GRANT         ->", _short(grant(ANA, source="web")))
        print("    розсилка      ->", _short(post_mkt()), "(MARKETING_EMAIL досі заблоковано)")
        print("    аналітика     ->", _short(user.post(f"/api/users/{sid}/analytics-event")))

        print("\n[7] Фонова відправка перевіряє згоду ще раз")
        grant(MKT, source="web")
        print("    GRANT + постановка в чергу ->", _short(post_mkt()))
        revoke(MKT, source="web")
        with app.app_context():
            print("    REVOKE, потім dispatch     ->", dispatch_pending_messages(), "(sent=0: відправку заблоковано)")
        print("   ", _outbox(sid))

        print("\n[8] Історія змін згод (user_consent_events)")
        with app.app_context():
            for e in ConsentEvent.query.filter_by(user_id=sid).order_by(ConsentEvent.id):
                print(f"    {e.occurred_at:%H:%M:%S}  {e.action:6} {e.purpose:18} "
                      f"policy={e.policy_version}  source={e.source:6} correlation_id={e.correlation_id}")
        print("\nТепер запустіть інтеграційний тест сценарію:")
        print("    python -m pytest tests/test_consent.py -v")
    finally:
        with app.app_context():
            ids = [sid, oid]
            OutboxMessage.query.filter(OutboxMessage.user_id.in_(ids)).delete(synchronize_session=False)
            ConsentEvent.query.filter(ConsentEvent.user_id.in_(ids)).delete(synchronize_session=False)
            UserConsent.query.filter(UserConsent.user_id.in_(ids)).delete(synchronize_session=False)
            PrivacyAuditEvent.query.filter(PrivacyAuditEvent.subject_id.in_(ids)).delete(
                synchronize_session=False)
            User.query.filter(User.id.in_(ids)).delete(synchronize_session=False)
            db.session.commit()


if __name__ == "__main__":
    main()
