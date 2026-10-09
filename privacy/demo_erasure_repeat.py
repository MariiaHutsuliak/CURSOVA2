"""
Live demo до Завдання 3, сценарій 4: повторна анонімізація від адміністратора.
Запуск з кореня проєкту:   python -m privacy.demo_erasure_repeat
Усі дані синтетичні, у кінці скрипт прибирає свої записи.
"""
from __future__ import annotations

import json
import uuid

from app import app
from models import db, User
from privacy.audit import PrivacyAuditEvent


def _show(resp) -> str:
    body = resp.get_json()
    keep = {k: body[k] for k in ("status", "error") if k in body}
    if "summary" in body:
        keep["summary"] = body["summary"]
    return f"{resp.status_code} {json.dumps(keep, ensure_ascii=False)}"


def _state(uid: int) -> str:
    with app.app_context():
        u = db.session.get(User, uid)
        return f"username={u.username} email={u.email} password_hash={u.password_hash}"


def main() -> None:
    tag = uuid.uuid4().hex[:6]
    with app.app_context():
        db.create_all()
        subject = User(username=f"demo.repeat.{tag}", email=f"demo.repeat.{tag}@example.com",
                       role="authorized_user")
        subject.set_password("DemoSubject-123")
        admin = User(username=f"demo.admin.{tag}", email=f"demo.admin.{tag}@example.com",
                     role="administrator")
        admin.set_password("DemoAdmin-456")
        db.session.add_all([subject, admin])
        db.session.commit()
        sid, aid, aname = subject.id, admin.id, admin.username

    try:
        client = app.test_client()
        client.post("/login", data={"username": aname, "password": "DemoAdmin-456"})
        url = f"/api/users/{sid}/anonymize"

        print(f"Суб'єкт id={sid}, адміністратор id={aid} (синтетичні)\n")
        print("[1] ДО:            ", _state(sid))
        print("[2] Адмін, 1-й запит:", _show(client.post(url, json={"confirm": True})))
        after_first = _state(sid)
        print("[3] ПІСЛЯ 1-го:    ", after_first)
        print("[4] Адмін, 2-й запит:", _show(client.post(url, json={"confirm": True})))
        after_second = _state(sid)
        print("[5] ПІСЛЯ 2-го:    ", after_second)
        print("\nСтан не змінився після повтору:", after_first == after_second)
    finally:
        with app.app_context():
            ids = [sid, aid]
            PrivacyAuditEvent.query.filter(PrivacyAuditEvent.subject_id.in_(ids)).delete(
                synchronize_session=False)
            User.query.filter(User.id.in_(ids)).delete(synchronize_session=False)
            db.session.commit()


if __name__ == "__main__":
    main()