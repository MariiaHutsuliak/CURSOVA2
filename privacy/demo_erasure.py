"""
Live demo до Завдання 3 (Right to Erasure): одноразовий СИНТЕТИЧНИЙ користувач.

  python -m privacy.demo_erasure setup     створює демо-користувача з пов'язаними записами
  python -m privacy.demo_erasure show      показує стан БД і файлу історії (до / після)
  python -m privacy.demo_erasure cleanup   прибирає всі демо-записи

Усі дані вигадані: реальних персональних даних тут немає.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from app import app
from history_utils import history_file, load_history, save_history
from models import db, User, UserRequest
from privacy.audit import PrivacyAuditEvent

USERNAME = "demo.erase"
EMAIL = "demo.erase@example.com"
PASSWORD = "DemoErase-123"
STATE_FILE = Path(tempfile.gettempdir()) / "lab4_demo_erasure_state.json"


def _read_state() -> dict:
    if not STATE_FILE.exists():
        sys.exit("Спочатку виконайте: python -m privacy.demo_erasure setup")
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))


def setup() -> None:
    with app.app_context():
        db.create_all()
        if User.query.filter_by(username=USERNAME).first():
            sys.exit("Демо-користувач уже існує. Спочатку: python -m privacy.demo_erasure cleanup")
        user = User(username=USERNAME, email=EMAIL, role="authorized_user")
        user.set_password(PASSWORD)
        user.api_history = [{"api": "Демо-запит", "params": f"email={EMAIL}",
                             "result": "ok", "timestamp": "2026-10-09 12:00:00"}]
        db.session.add(user)
        db.session.flush()
        own = UserRequest(full_name="Demo Erase", email=EMAIL, phone="+380509998877",
                          password_hash="pbkdf2:sha256:DEMO-SYNTHETIC-HASH", status="approved")
        other = UserRequest(full_name="Other Person", email="demo.other@example.com",
                            phone="+380507776655", password_hash="pbkdf2:sha256:DEMO-OTHER-HASH",
                            status="approved", reviewed_by=user.id)
        db.session.add_all([own, other])
        db.session.commit()
        state = {"user_id": user.id, "request_ids": [own.id, other.id]}
        user_id = user.id

    path = history_file(user_id)
    if path.exists():
        sys.exit(f"{path} уже існує: це не демо-файл, нічого не чіпаю. Виконайте cleanup.")
    save_history(user_id, [
        {"api": "Запит 1", "params": f"phone=+380509998877", "result": "ok", "timestamp": "2026-10-09 12:05:00"},
        {"api": "Запит 2", "params": "місяць: 4", "result": "ok", "timestamp": "2026-10-09 12:06:00"},
    ])
    STATE_FILE.write_text(json.dumps(state), encoding="utf-8")

    print(f"Створено демо-користувача id={user_id}: логін {USERNAME}, пароль {PASSWORD}")
    print("\nКоманда для консолі браузера (після входу під цим користувачем):\n")
    print(f"fetch('/api/users/{user_id}/anonymize', {{method: 'POST', headers: "
          f"{{'Content-Type': 'application/json'}}, body: JSON.stringify({{confirm: true}})}})"
          f".then(r => r.json().then(j => console.log(r.status, j)))")


def show() -> None:
    state = _read_state()
    uid = state["user_id"]
    with app.app_context():
        user = db.session.get(User, uid)
        print("== users ==")
        if user is None:
            print(f"id={uid}: запису немає")
        else:
            print(f"id={user.id}  username={user.username!r}  email={user.email!r}")
            print(f"       password_hash={str(user.password_hash)[:34]!r}  active={user.is_active_flag}"
                  f"  role={user.role!r}  api_history={len(user.api_history or [])} запис(ів)")

        print("\n== user_requests (власна заявка та заявка, яку розглянув користувач) ==")
        for rid in state["request_ids"]:
            r = db.session.get(UserRequest, rid)
            if r is None:
                print(f"id={rid}: запису немає")
                continue
            print(f"id={r.id}  full_name={r.full_name!r}  email={r.email!r}  phone={r.phone!r}")
            print(f"       status={r.status!r}  reviewed_by={r.reviewed_by}  "
                  f"password_hash={str(r.password_hash)[:34]!r}")

        print("\n== privacy_audit_events ==")
        events = PrivacyAuditEvent.query.filter_by(subject_id=uid).order_by(PrivacyAuditEvent.id).all()
        if not events:
            print("(подій ще немає)")
        for e in events:
            print(f"id={e.id}  {e.event_type}  outcome={e.outcome}  actor_id={e.actor_id}  "
                  f"subject_id={e.subject_id}  correlation_id={e.correlation_id}  details={e.details}")

    path = history_file(uid)
    print("\n== history file ==")
    print(f"{path}: " + (f"існує, {len(load_history(uid))} запис(ів)" if path.exists() else "ВИДАЛЕНО"))


def cleanup() -> None:
    if not STATE_FILE.exists():
        print("Нічого прибирати.")
        return
    state = _read_state()
    with app.app_context():
        PrivacyAuditEvent.query.filter_by(subject_id=state["user_id"]).delete()
        UserRequest.query.filter(UserRequest.id.in_(state["request_ids"])).delete(synchronize_session=False)
        User.query.filter_by(id=state["user_id"]).delete()
        db.session.commit()
    history_file(state["user_id"]).unlink(missing_ok=True)
    STATE_FILE.unlink(missing_ok=True)
    print("Демо-записи видалено.")


if __name__ == "__main__":
    commands = {"setup": setup, "show": show, "cleanup": cleanup}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        sys.exit("Використання: python -m privacy.demo_erasure setup|show|cleanup")
    commands[sys.argv[1]]()
