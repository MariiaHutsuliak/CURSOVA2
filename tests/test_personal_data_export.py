"""
Інтеграційні тести Завдання 2: Right of Access та Personal Data Export
(GET /api/users/<id>/personal-data).

Тести створюють власних СИНТЕТИЧНИХ користувачів з унікальними іменами, контрольні
записи в кожному джерелі даних і повністю прибирають їх після себе.

Контрольні записи:
  * users                 - профіль (email, username)
  * users.api_history     - маркер CTRL-COL-*
  * history/user_<id>.json - маркер CTRL-HIST-*
  * user_requests         - заявка з телефоном
  * запис, що є в обох сховищах історії одночасно (перевірка відсутності дублів)

Запуск:  python -m pytest tests/test_personal_data_export.py -v
"""
import json
import logging
import uuid

import pytest

from app import app as flask_app
from history_utils import history_file, save_history
from models import db, User, UserRequest

PASSWORD_A = "Synthetic" + "PassA-123"
PASSWORD_B = "Synthetic" + "PassB-456"
PASSWORD_ADMIN = "SyntheticPassAdmin-789"

FORBIDDEN_KEYS = {"password_hash", "password", "role", "is_active_flag", "reviewed_by", "token"}


def _make_user(username, email, password, role="authorized_user"):
    user = User(username=username, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.flush()
    return user


def _login(username, password):
    client = flask_app.test_client()
    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == 302, "synthetic user could not log in"
    return client


def _walk_keys(node):
    if isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from _walk_keys(v)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_keys(item)


@pytest.fixture
def env():
    tag = uuid.uuid4().hex[:8]
    flask_app.config["TESTING"] = True
    created_files = []
    with flask_app.app_context():
        db.create_all()                      # нові таблиці (згоди, аудит) мають існувати
        a = _make_user(f"exp-a-{tag}", f"exp-a-{tag}@example.com", PASSWORD_A)
        b = _make_user(f"exp-b-{tag}", f"exp-b-{tag}@example.com", PASSWORD_B)
        admin = _make_user(f"exp-admin-{tag}", f"exp-admin-{tag}@example.com",
                           PASSWORD_ADMIN, role="administrator")
        dup = {"api": f"DUP-{tag}", "params": "p", "result": "r", "timestamp": "2026-01-01 09:00:00"}
        a.api_history = [
            {"api": f"CTRL-COL-A-{tag}", "params": "p", "result": "r", "timestamp": "2026-01-01 10:00:00"},
            dup,
        ]
        b.api_history = [{"api": f"CTRL-COL-B-{tag}", "params": "p", "result": "r",
                          "timestamp": "2026-01-02 10:00:00"}]
        db.session.add_all([
            UserRequest(full_name=f"Alice Synthetic {tag}", email=a.email, phone="+380501110001",
                        password_hash="pbkdf2:sha256:SYNTHETIC-HASH-A", status="approved"),
            UserRequest(full_name=f"Bob Synthetic {tag}", email=b.email, phone="+380502220002",
                        password_hash="pbkdf2:sha256:SYNTHETIC-HASH-B", status="approved"),
        ])
        db.session.commit()

        ids = {"a": a.id, "b": b.id, "admin": admin.id}
        info = {
            "tag": tag, "ids": ids,
            "a_user": a.username, "b_user": b.username, "admin_user": admin.username,
            "a_email": a.email, "b_email": b.email,
            "a_hash": a.password_hash, "b_hash": b.password_hash,
            "dup": dup,
        }

    def cleanup():
        with flask_app.app_context():
            UserRequest.query.filter(
                UserRequest.email.in_([info["a_email"], info["b_email"]])).delete(
                synchronize_session=False)
            User.query.filter(User.id.in_(list(ids.values()))).delete(synchronize_session=False)
            db.session.commit()
        for path in created_files:
            path.unlink(missing_ok=True)

    try:
        histories = {
            "a": [{"api": f"CTRL-HIST-A-{tag}", "params": "p", "result": "r",
                   "timestamp": "2026-01-01 11:00:00"}, dup],
            "b": [{"api": f"CTRL-HIST-B-{tag}", "params": "p", "result": "r",
                   "timestamp": "2026-01-02 11:00:00"}],
        }
        # Реальні файли історії ніколи не перезаписуємо: у разі збігу ID тест пропускається.
        for key in histories:
            if history_file(ids[key]).exists():
                pytest.skip(f"{history_file(ids[key])} already exists; refusing to overwrite real history")
        for key, hist in histories.items():
            save_history(ids[key], hist)
            created_files.append(history_file(ids[key]))
        yield info
    finally:
        cleanup()


# --- Успішний експорт власних даних --------------------------------------------

def test_owner_gets_complete_structured_export(env):
    tag, ids = env["tag"], env["ids"]
    resp = _login(env["a_user"], PASSWORD_A).get(f"/api/users/{ids['a']}/personal-data")
    body = resp.get_json()

    assert resp.status_code == 200
    assert resp.content_type == "application/json"
    assert resp.headers["Cache-Control"] == "no-store"

    # стабільний контракт
    assert body["schema_version"] == "1.0"
    assert set(body) == {"schema_version", "metadata", "subject", "profile", "settings",
                         "activity_history", "registration_requests", "consents"}
    meta = body["metadata"]
    assert meta["time_zone"] == "UTC" and meta["generated_at"].endswith("+00:00")
    assert meta["categories"] == ["profile", "settings", "activity_history",
                                  "registration_requests", "consents"]
    assert meta["correlation_id"] and meta["correlation_id"] == resp.headers["X-Correlation-ID"]
    assert body["subject"] == {"id": ids["a"]}

    # контрольні записи з КОЖНОГО джерела
    assert body["profile"]["data"]["email"] == env["a_email"]
    assert body["profile"]["data"]["username"] == env["a_user"]
    assert body["profile"]["data"]["created_at"].endswith("+00:00")
    apis = [e["api"] for e in body["activity_history"]["data"]]
    assert f"CTRL-COL-A-{tag}" in apis                 # users.api_history
    assert f"CTRL-HIST-A-{tag}" in apis                # history/user_<id>.json
    reqs = body["registration_requests"]["data"]
    assert len(reqs) == 1 and reqs[0]["phone"] == "+380501110001"
    assert reqs[0]["status"] == "approved"

    # відсутні категорії - передбачувана порожня структура (documented omission)
    for name in ("settings", "consents"):
        section = body[name]
        assert set(section) >= {"source", "time_zone", "available", "data"}
        assert section["available"] in (True, False)
    assert body["settings"] == {"source": None, "time_zone": None, "available": False,
                                "data": {}, "note": "The system stores no user-configurable settings."}


def test_no_duplicates_between_history_sources(env):
    resp = _login(env["a_user"], PASSWORD_A).get(f"/api/users/{env['ids']['a']}/personal-data")
    dup_api = env["dup"]["api"]
    entries = [e for e in resp.get_json()["activity_history"]["data"] if e["api"] == dup_api]
    assert len(entries) == 1


def test_export_schema_is_stable_between_calls(env):
    client = _login(env["a_user"], PASSWORD_A)
    url = f"/api/users/{env['ids']['a']}/personal-data"

    def normalise(doc):
        doc["metadata"].pop("generated_at")
        doc["metadata"].pop("correlation_id")
        return doc

    assert normalise(client.get(url).get_json()) == normalise(client.get(url).get_json())


# --- Мінімізація ----------------------------------------------------------------

def test_security_sensitive_fields_are_excluded(env):
    resp = _login(env["a_user"], PASSWORD_A).get(f"/api/users/{env['ids']['a']}/personal-data")
    body = resp.get_json()
    raw = resp.get_data(as_text=True)

    assert not FORBIDDEN_KEYS & set(_walk_keys(body))
    assert env["a_hash"] not in raw and "pbkdf2" not in raw and "SYNTHETIC-HASH" not in raw
    assert PASSWORD_A not in raw
    # відсутність зазначена явно (documented omission)
    assert "users.password_hash" in body["metadata"]["omitted_fields"]


def test_export_does_not_mix_data_of_other_users(env):
    resp = _login(env["a_user"], PASSWORD_A).get(f"/api/users/{env['ids']['a']}/personal-data")
    raw = resp.get_data(as_text=True)
    for foreign in (env["b_email"], env["b_user"], f"CTRL-HIST-B-{env['tag']}",
                    f"CTRL-COL-B-{env['tag']}", "+380502220002"):
        assert foreign not in raw


def test_admin_export_does_not_include_requests_reviewed_by_admin(env):
    with flask_app.app_context():
        req = UserRequest.query.filter_by(email=env["b_email"]).first()
        req.reviewed_by = env["ids"]["admin"]
        db.session.commit()
    resp = _login(env["admin_user"], PASSWORD_ADMIN).get(
        f"/api/users/{env['ids']['admin']}/personal-data")
    raw = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert env["b_email"] not in raw and "+380502220002" not in raw


# --- Контроль доступу ------------------------------------------------------------

def test_other_user_is_denied_without_any_data(env):
    client_a = _login(env["a_user"], PASSWORD_A)
    resp = client_a.get(f"/api/users/{env['ids']['b']}/personal-data")
    raw = resp.get_data(as_text=True)

    assert resp.status_code == 403
    assert resp.get_json() == {"error": "forbidden"}
    for leaked in (env["b_email"], env["b_user"], "CTRL-", "+380502220002", env["b_hash"]):
        assert leaked not in raw


def test_denial_does_not_reveal_whether_foreign_profile_exists(env):
    client_a = _login(env["a_user"], PASSWORD_A)
    existing = client_a.get(f"/api/users/{env['ids']['b']}/personal-data")
    missing = client_a.get(f"/api/users/{env['ids']['b'] + 100000}/personal-data")

    assert existing.status_code == missing.status_code == 403
    assert existing.get_data() == missing.get_data()


def test_unauthenticated_request_is_rejected_without_data(env):
    resp = flask_app.test_client().get(f"/api/users/{env['ids']['a']}/personal-data")
    assert resp.status_code == 401
    assert resp.get_json() == {"error": "unauthorized"}
    assert env["a_email"] not in resp.get_data(as_text=True)


def test_privileged_role_can_export_other_user(env):
    resp = _login(env["admin_user"], PASSWORD_ADMIN).get(
        f"/api/users/{env['ids']['b']}/personal-data")
    assert resp.status_code == 200
    assert resp.get_json()["profile"]["data"]["email"] == env["b_email"]


def test_nonexistent_subject_for_privileged_role_is_404(env):
    resp = _login(env["admin_user"], PASSWORD_ADMIN).get(
        f"/api/users/{env['ids']['b'] + 100000}/personal-data")
    assert resp.status_code == 404
    assert resp.get_json() == {"error": "not_found"}


def test_corrupted_history_file_is_reported_not_silently_skipped(env):
    history_file(env["ids"]["a"]).write_text("{not valid json", encoding="utf-8")
    resp = _login(env["a_user"], PASSWORD_A).get(f"/api/users/{env['ids']['a']}/personal-data")
    body = resp.get_json()
    assert resp.status_code == 200
    assert any("unreadable" in w for w in body["metadata"]["warnings"])
    assert any(e["api"].startswith("CTRL-COL-A-") for e in body["activity_history"]["data"])


# --- Витік через логи -------------------------------------------------------------

class _RawCapture(logging.Handler):
    """Бачить записи ДО санітизації (стоїть першим), тому перевіряє, що саме пише код."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.lines = []

    def emit(self, record):
        extras = {k: v for k, v in record.__dict__.items()
                  if k not in logging.makeLogRecord({}).__dict__}
        self.lines.append((record.name, record.getMessage(), extras))


def test_export_does_not_leak_pii_or_full_json_into_logs(env):
    root = logging.getLogger()
    capture = _RawCapture()
    root.handlers.insert(0, capture)
    try:
        client_a = _login(env["a_user"], PASSWORD_A)
        client_a.get(f"/api/users/{env['ids']['a']}/personal-data")        # успіх
        client_a.get(f"/api/users/{env['ids']['b']}/personal-data")        # відмова
    finally:
        root.handlers.remove(capture)

    text = json.dumps(capture.lines, ensure_ascii=False, default=str)
    for leaked in (env["a_email"], env["b_email"], env["a_user"], env["b_user"],
                   "+380501110001", env["a_hash"], PASSWORD_A, "CTRL-", "schema_version"):
        assert leaked not in text, f"{leaked!r} leaked into logs"

    events = [e for name, _, e in capture.lines
              if name == "security" and e.get("operation") == "personal_data_export"]
    assert {e["outcome"] for e in events} == {"success", "denied"}
    ok = next(e for e in events if e["outcome"] == "success")
    assert ok["actor_id"] == env["ids"]["a"] and ok["subject_id"] == env["ids"]["a"]
    denied = next(e for e in events if e["outcome"] == "denied")
    assert denied["actor_id"] == env["ids"]["a"] and denied["subject_id"] == env["ids"]["b"]
