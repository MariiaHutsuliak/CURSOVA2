"""
Інтеграційні тести Завдання 3: Right to Erasure та Anonymization Workflow
(POST /api/users/<id>/anonymize).

Підготовка: синтетичний користувач A із пов'язаними записами в КОЖНОМУ охопленому джерелі
(users, users.api_history, history/user_<id>.json, user_requests двох видів), а також
користувач B та заявка, яку розглянув A (бізнес-запис, що має ЗАЛИШИТИСЬ).

Перевіряється: відсутність початкових PII в усіх джерелах, збереження бізнес-записів,
цілісність зв'язків, повторний запуск, відкат при збої, заборона для стороннього actor,
privacy-safe audit.

Запуск:  python -m pytest tests/test_erasure.py -v
"""
import json
import logging
import uuid

import pytest

from app import app as flask_app
from history_utils import history_file, save_history
from models import db, User, UserRequest
from privacy import erasure
from privacy.audit import PrivacyAuditEvent
from privacy.erasure import ERASURE_POLICY

PASSWORD_A = "Synthetic" + "PassA-123"
PASSWORD_B = "Synthetic" + "PassB-456"
PASSWORD_ADMIN = "SyntheticPassAdmin-789"
CONFIRM = {"confirm": True}


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


def _anonymize(client, subject_id, body=CONFIRM):
    return client.post(f"/api/users/{subject_id}/anonymize", json=body)


@pytest.fixture
def env():
    tag = uuid.uuid4().hex[:8]
    flask_app.config["TESTING"] = True
    created_files = []
    with flask_app.app_context():
        db.create_all()                      # створює нову таблицю privacy_audit_events
        a = _make_user(f"erase-a-{tag}", f"erase-a-{tag}@example.com", PASSWORD_A)
        b = _make_user(f"erase-b-{tag}", f"erase-b-{tag}@example.com", PASSWORD_B)
        admin = _make_user(f"erase-admin-{tag}", f"erase-admin-{tag}@example.com",
                           PASSWORD_ADMIN, role="administrator")
        a.api_history = [{"api": "q", "params": f"email=erase-a-{tag}@example.com",
                          "result": "r", "timestamp": "2026-01-01 10:00:00"}]
        req_a1 = UserRequest(full_name=f"Alice Synthetic {tag}", email=a.email, phone="+380501110001",
                             password_hash="pbkdf2:sha256:SYNTHETIC-HASH-A1", status="approved")
        req_a2 = UserRequest(full_name=f"Alice Again {tag}", email=a.email.upper(),   # інший регістр
                             phone="+380501110002", password_hash="pbkdf2:sha256:SYNTHETIC-HASH-A2",
                             status="rejected")
        req_b = UserRequest(full_name=f"Bob Synthetic {tag}", email=b.email, phone="+380502220002",
                            password_hash="pbkdf2:sha256:SYNTHETIC-HASH-B", status="approved")
        db.session.add_all([req_a1, req_a2, req_b])
        db.session.flush()
        req_b.reviewed_by = a.id             # A розглянув заявку B: бізнес-запис, що має лишитись
        db.session.commit()

        info = {
            "tag": tag,
            "ids": {"a": a.id, "b": b.id, "admin": admin.id},
            "req_ids": [req_a1.id, req_a2.id, req_b.id],
            "req_a_ids": [req_a1.id, req_a2.id], "req_b_id": req_b.id,
            "a_user": a.username, "a_email": a.email, "a_hash": a.password_hash,
            "b_user": b.username, "b_email": b.email, "admin_user": admin.username,
            "a_pii": [a.username, a.email, a.email.upper(), a.password_hash,
                      f"Alice Synthetic {tag}", f"Alice Again {tag}", "+380501110001",
                      "+380501110002", "SYNTHETIC-HASH-A1", "SYNTHETIC-HASH-A2"],
        }

    def cleanup():
        with flask_app.app_context():
            PrivacyAuditEvent.query.filter(
                PrivacyAuditEvent.subject_id.in_(list(info["ids"].values()))).delete(
                synchronize_session=False)
            UserRequest.query.filter(UserRequest.id.in_(info["req_ids"])).delete(
                synchronize_session=False)
            User.query.filter(User.id.in_(list(info["ids"].values()))).delete(
                synchronize_session=False)
            db.session.commit()
        for path in created_files:
            path.unlink(missing_ok=True)

    try:
        path = history_file(info["ids"]["a"])
        if path.exists():
            pytest.skip(f"{path} already exists; refusing to overwrite real history")
        save_history(info["ids"]["a"], [{"api": "q", "params": f"phone=+380501110001 {tag}",
                                         "result": "r", "timestamp": "2026-01-01 11:00:00"}])
        created_files.append(path)
        info["a_history_path"] = path
        yield info
    finally:
        cleanup()


def _dump_storage_text():
    """Текстовий дамп усіх охоплених сховищ: users, user_requests, audit, файли історії."""
    parts = []
    with flask_app.app_context():
        for model in (User, UserRequest, PrivacyAuditEvent):
            for row in model.query.all():
                parts.append(json.dumps(
                    {c.name: str(getattr(row, c.name)) for c in model.__table__.columns},
                    ensure_ascii=False))
    from history_utils import HISTORY_DIR
    for path in HISTORY_DIR.glob("user_*.json"):
        parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)


def _user_state(user_id):
    with flask_app.app_context():
        u = db.session.get(User, user_id)
        return (u.username, u.email, u.password_hash, u.is_active_flag, json.dumps(u.api_history))


def _requests_state(ids):
    with flask_app.app_context():
        return [(r.id, r.full_name, r.email, r.phone, r.password_hash, r.status, r.reviewed_by)
                for r in UserRequest.query.filter(UserRequest.id.in_(ids)).order_by(UserRequest.id)]


# --- Політика ---------------------------------------------------------------------

def test_policy_assigns_valid_action_to_every_entity():
    assert ERASURE_POLICY
    actions = {action for _, action, _ in ERASURE_POLICY}
    assert actions <= {"DELETE", "ANONYMIZE", "RETAIN", "SKIP"}
    assert {"DELETE", "ANONYMIZE", "RETAIN", "SKIP"} == actions
    assert all(reason.strip() for _, _, reason in ERASURE_POLICY)


# --- Основний сценарій ------------------------------------------------------------

def test_before_state_contains_pii_in_every_source(env):
    """Контроль: до операції початкові PII справді є в усіх сховищах (тест не 'порожній')."""
    dump = _dump_storage_text()
    for value in (env["a_email"], env["a_user"], "+380501110001", "SYNTHETIC-HASH-A1"):
        assert value in dump
    assert env["a_history_path"].exists()


def test_self_anonymization_removes_pii_from_all_sources(env):
    client = _login(env["a_user"], PASSWORD_A)
    resp = _anonymize(client, env["ids"]["a"])
    body = resp.get_json()

    assert resp.status_code == 200
    assert body["status"] == "anonymized"
    assert body["subject_id"] == env["ids"]["a"]
    assert body["summary"] == {"users_anonymized": 1, "user_requests_anonymized": 2,
                               "consents_withdrawn": 0, "activity_history_cleared": True,
                               "history_file_deleted": True}
    assert body["correlation_id"] == resp.headers["X-Correlation-ID"]

    dump = _dump_storage_text()
    leaked = [v for v in env["a_pii"] if v in dump]
    assert not leaked, f"PII залишилась у сховищах: {leaked}"
    assert not env["a_history_path"].exists()

    with flask_app.app_context():
        u = db.session.get(User, env["ids"]["a"])
        assert u.username.startswith("anon-") and u.email.endswith("@anon.local")
        assert u.is_active_flag is False and u.api_history == []
        assert u.password_hash == erasure.UNUSABLE_PASSWORD_HASH


def test_business_records_survive_with_intact_references(env):
    with flask_app.app_context():
        users_before = User.query.count()
        requests_before = UserRequest.query.count()

    _anonymize(_login(env["a_user"], PASSWORD_A), env["ids"]["a"])

    with flask_app.app_context():
        assert User.query.count() == users_before                 # жодного рядка не втрачено
        assert UserRequest.query.count() == requests_before

        # анонімізовані заявки A лишились як записи про рішення (статус збережено)
        rows = {r.id: r for r in UserRequest.query.filter(UserRequest.id.in_(env["req_a_ids"]))}
        assert {r.status for r in rows.values()} == {"approved", "rejected"}
        assert all(r.full_name == "Anonymized" and r.phone is None for r in rows.values())

        # заявка B, яку розглянув A, лишилась без змін, а reviewed_by веде на анонімізований акаунт
        req_b = db.session.get(UserRequest, env["req_b_id"])
        assert req_b.full_name == f"Bob Synthetic {env['tag']}" and req_b.phone == "+380502220002"
        assert req_b.reviewed_by == env["ids"]["a"]
        assert req_b.reviewer is not None and req_b.reviewer.username.startswith("anon-")

        # немає осиротілих зв'язків: кожен reviewed_by вказує на існуючого користувача
        orphans = (UserRequest.query.outerjoin(User, UserRequest.reviewed_by == User.id)
                   .filter(UserRequest.reviewed_by.isnot(None), User.id.is_(None)).count())
        assert orphans == 0
        # дані B не зачеплені
        b = db.session.get(User, env["ids"]["b"])
        assert b.email == env["b_email"] and b.username == env["b_user"]


def test_new_values_are_unique_random_and_not_derived_from_originals(env):
    with flask_app.app_context():
        c = _make_user(f"erase-c-{env['tag']}", f"erase-c-{env['tag']}@example.com", "SyntheticPassC-1")
        db.session.commit()
        c_id = c.id
    try:
        admin = _login(env["admin_user"], PASSWORD_ADMIN)
        assert _anonymize(admin, env["ids"]["a"]).status_code == 200
        assert _anonymize(admin, c_id).status_code == 200
        with flask_app.app_context():
            ua, uc = db.session.get(User, env["ids"]["a"]), db.session.get(User, c_id)
            assert ua.email != uc.email and ua.username != uc.username    # unique constraint
            for original in (env["tag"], "erase"):
                assert original not in ua.email and original not in ua.username
    finally:
        with flask_app.app_context():
            PrivacyAuditEvent.query.filter_by(subject_id=c_id).delete()
            User.query.filter_by(id=c_id).delete()
            db.session.commit()


def test_old_credentials_no_longer_work_and_session_is_closed(env):
    client = _login(env["a_user"], PASSWORD_A)
    assert _anonymize(client, env["ids"]["a"]).status_code == 200

    # сесію завершено: експорт тепер вимагає автентифікації
    assert client.get(f"/api/users/{env['ids']['a']}/personal-data").status_code == 401
    # старі облікові дані не працюють
    fresh = flask_app.test_client()
    assert fresh.post("/login", data={"username": env["a_user"], "password": PASSWORD_A}).status_code == 200
    with flask_app.app_context():
        anon_name = db.session.get(User, env["ids"]["a"]).username
    assert fresh.post("/login", data={"username": anon_name, "password": PASSWORD_A}).status_code == 200
    assert fresh.get("/api/users/%d/personal-data" % env["ids"]["a"]).status_code == 401


# --- Ідемпотентність і збій --------------------------------------------------------

def test_repeated_request_is_idempotent_and_does_not_restore_or_create(env):
    admin = _login(env["admin_user"], PASSWORD_ADMIN)
    assert _anonymize(admin, env["ids"]["a"]).get_json()["status"] == "anonymized"
    snapshot = (_user_state(env["ids"]["a"]), _requests_state(env["req_ids"]))
    with flask_app.app_context():
        users_count = User.query.count()

    again = _anonymize(admin, env["ids"]["a"])
    assert again.status_code == 200
    assert again.get_json()["status"] == "already_anonymized"
    assert again.get_json()["summary"]["users_anonymized"] == 0

    assert (_user_state(env["ids"]["a"]), _requests_state(env["req_ids"])) == snapshot
    with flask_app.app_context():
        assert User.query.count() == users_count                  # нових профілів немає
        outcomes = [e.outcome for e in PrivacyAuditEvent.query.filter_by(
            subject_id=env["ids"]["a"]).order_by(PrivacyAuditEvent.id)]
    assert outcomes == ["success", "noop"]


def test_repeat_cleans_leftover_history_file(env):
    """Імітація часткового збою: файл не було видалено після commit - повтор його дочищає."""
    admin = _login(env["admin_user"], PASSWORD_ADMIN)
    _anonymize(admin, env["ids"]["a"])
    save_history(env["ids"]["a"], [{"api": "leftover", "params": "x", "result": "y", "timestamp": "t"}])
    assert env["a_history_path"].exists()

    resp = _anonymize(admin, env["ids"]["a"])
    assert resp.get_json()["summary"]["history_file_deleted"] is True
    assert not env["a_history_path"].exists()


def test_failure_in_the_middle_rolls_back_everything_and_can_be_retried(env, monkeypatch):
    before = (_user_state(env["ids"]["a"]), _requests_state(env["req_ids"]))
    client = _login(env["a_user"], PASSWORD_A)

    def boom(original_email):
        raise RuntimeError("simulated failure after the users row was changed")

    monkeypatch.setattr(erasure, "_anonymize_requests", boom)
    resp = _anonymize(client, env["ids"]["a"])

    assert resp.status_code == 500
    assert resp.get_json()["error"] == "erasure_failed"
    assert (_user_state(env["ids"]["a"]), _requests_state(env["req_ids"])) == before   # повний відкат
    assert env["a_history_path"].exists()                                               # файл не чіпали
    with flask_app.app_context():
        events = PrivacyAuditEvent.query.filter_by(subject_id=env["ids"]["a"]).all()
        assert [(e.outcome, e.event_type) for e in events] == [("failure", "USER_ANONYMIZED")]

    monkeypatch.undo()                                    # безпечне продовження після збою
    retry = _anonymize(client, env["ids"]["a"])
    assert retry.status_code == 200 and retry.get_json()["status"] == "anonymized"
    assert not [v for v in env["a_pii"] if v in _dump_storage_text()]


# --- Авторизація та підтвердження -------------------------------------------------

def test_foreign_actor_is_denied_and_nothing_changes(env):
    before = (_user_state(env["ids"]["a"]), _requests_state(env["req_ids"]))
    client_b = _login(env["b_user"], PASSWORD_B)

    denied = _anonymize(client_b, env["ids"]["a"])
    missing = _anonymize(client_b, env["ids"]["a"] + 100000)

    assert denied.status_code == missing.status_code == 403
    assert denied.get_data() == missing.get_data()           # факт існування не розкривається
    assert denied.get_json() == {"error": "forbidden"}
    assert (_user_state(env["ids"]["a"]), _requests_state(env["req_ids"])) == before
    assert env["a_history_path"].exists()


def test_unauthenticated_and_get_requests_are_rejected(env):
    anon = flask_app.test_client()
    assert _anonymize(anon, env["ids"]["a"]).status_code == 401
    client = _login(env["a_user"], PASSWORD_A)
    assert client.get(f"/api/users/{env['ids']['a']}/anonymize").status_code == 405
    assert env["a_email"] in _dump_storage_text()


@pytest.mark.parametrize("body", [None, {}, {"confirm": False}, {"confirm": "true"}])
def test_confirmation_is_required(env, body):
    client = _login(env["a_user"], PASSWORD_A)
    resp = client.post(f"/api/users/{env['ids']['a']}/anonymize", json=body) \
        if body is not None else client.post(f"/api/users/{env['ids']['a']}/anonymize")
    assert resp.status_code == 400 and resp.get_json() == {"error": "confirmation_required"}
    assert env["a_email"] in _dump_storage_text()


def test_form_encoded_cross_site_style_request_is_not_accepted(env):
    client = _login(env["a_user"], PASSWORD_A)
    resp = client.post(f"/api/users/{env['ids']['a']}/anonymize", data={"confirm": "true"})
    assert resp.status_code == 400
    assert env["a_email"] in _dump_storage_text()


def test_privileged_role_can_anonymize_other_user_and_missing_subject_is_404(env):
    admin = _login(env["admin_user"], PASSWORD_ADMIN)
    assert _anonymize(admin, env["ids"]["b"]).status_code == 200
    missing = _anonymize(admin, env["ids"]["b"] + 100000)
    assert missing.status_code == 404 and missing.get_json() == {"error": "not_found"}


# --- Audit ------------------------------------------------------------------------

def test_audit_event_is_privacy_safe(env):
    client = _login(env["a_user"], PASSWORD_A)
    resp = _anonymize(client, env["ids"]["a"])

    with flask_app.app_context():
        event = PrivacyAuditEvent.query.filter_by(subject_id=env["ids"]["a"]).one()
        assert event.event_type == "USER_ANONYMIZED" and event.outcome == "success"
        assert event.actor_id == env["ids"]["a"]
        assert event.correlation_id == resp.get_json()["correlation_id"]
        assert event.created_at is not None
        assert all(isinstance(v, (int, bool)) for v in event.details.values())
        row_text = json.dumps({c.name: str(getattr(event, c.name))
                               for c in PrivacyAuditEvent.__table__.columns})
    assert not [v for v in env["a_pii"] if v in row_text]       # audit не резервне сховище PII


class _RawCapture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.lines = []

    def emit(self, record):
        extras = {k: v for k, v in record.__dict__.items()
                  if k not in logging.makeLogRecord({}).__dict__}
        self.lines.append((record.name, record.getMessage(), extras))


def test_logs_do_not_contain_deleted_values(env):
    root = logging.getLogger()
    capture = _RawCapture()
    root.handlers.insert(0, capture)
    try:
        _anonymize(_login(env["a_user"], PASSWORD_A), env["ids"]["a"])
    finally:
        root.handlers.remove(capture)
    text = json.dumps(capture.lines, ensure_ascii=False, default=str)
    assert not [v for v in env["a_pii"] if v in text]
    events = [e for name, _, e in capture.lines
              if name == "security" and e.get("operation") == "anonymize_user"]
    assert [e["outcome"] for e in events] == ["success"]
