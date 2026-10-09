"""
Інтеграційні тести Завдання 4: Consent Management Engine.

Головний сценарій:  початковий DENY -> GRANT -> ALLOW (+ побічний ефект) -> REVOKE ->
DENY (БЕЗ побічного ефекту). Окремо: ізоляція цілей, історія й докази, ідемпотентність,
версія політики, фонова відправка, авторизація, незалежність системних функцій.

Запуск:  python -m pytest tests/test_consent.py -v
"""
import json
import logging
import uuid

import pytest

from app import app as flask_app
from models import db, User
from privacy import consent
from privacy.audit import PrivacyAuditEvent
from privacy.consent import (
    ConsentEvent, ConsentPolicyGate, OutboxMessage, UserConsent, dispatch_pending_messages,
)

MKT, ANA = "MARKETING_EMAIL", "OPTIONAL_ANALYTICS"
PASSWORDS = {"a": "SyntheticPassA-123", "b": "SyntheticPassB-456",
             "op": "SyntheticPassOp-789", "admin": "SyntheticPassAdmin-000"}


def _login(username, password):
    client = flask_app.test_client()
    assert client.post("/login", data={"username": username, "password": password}).status_code == 302
    return client


def _grant(client, uid, purpose, **body):
    return client.post(f"/api/users/{uid}/consents/{purpose}/grant", json=body)


def _revoke(client, uid, purpose, **body):
    return client.post(f"/api/users/{uid}/consents/{purpose}/revoke", json=body)


def _send_marketing(client, uid):
    return client.post(f"/api/users/{uid}/marketing-email")


def _count(model, **filters):
    with flask_app.app_context():
        return model.query.filter_by(**filters).count()


@pytest.fixture
def env():
    tag = uuid.uuid4().hex[:8]
    flask_app.config["TESTING"] = True
    with flask_app.app_context():
        db.create_all()
        users = {}
        for key, role in (("a", "authorized_user"), ("b", "authorized_user"),
                          ("op", "operator"), ("admin", "administrator")):
            u = User(username=f"consent-{key}-{tag}", email=f"consent-{key}-{tag}@example.com", role=role)
            u.set_password(PASSWORDS[key])
            db.session.add(u)
            users[key] = u
        db.session.commit()
        info = {"tag": tag, "ids": {k: u.id for k, u in users.items()},
                "names": {k: u.username for k, u in users.items()},
                "emails": {k: u.email for k, u in users.items()}}

    yield info

    ids = list(info["ids"].values())
    with flask_app.app_context():
        OutboxMessage.query.filter(OutboxMessage.user_id.in_(ids)).delete(synchronize_session=False)
        ConsentEvent.query.filter(ConsentEvent.user_id.in_(ids)).delete(synchronize_session=False)
        UserConsent.query.filter(UserConsent.user_id.in_(ids)).delete(synchronize_session=False)
        PrivacyAuditEvent.query.filter(PrivacyAuditEvent.subject_id.in_(ids)).delete(
            synchronize_session=False)
        User.query.filter(User.id.in_(ids)).delete(synchronize_session=False)
        db.session.commit()


def client_for(env, key):
    return _login(env["names"][key], PASSWORDS[key])


# --- Головний сценарій GRANT -> ALLOW -> REVOKE -> DENY -----------------------------

def test_grant_allow_revoke_deny_scenario(env):
    a, op = env["ids"]["a"], client_for(env, "op")
    user_a = client_for(env, "a")
    uid = env["ids"]["a"]

    # 0. початковий стан: DENY, побічного ефекту немає
    denied = _send_marketing(op, uid)
    assert denied.status_code == 403
    assert denied.get_json() == {"error": "consent_required", "purpose": MKT, "reason": "no_consent"}
    assert _count(OutboxMessage, user_id=uid) == 0

    # 1. GRANT
    granted = _grant(user_a, uid, MKT, policy_version="2026-10-01", source="web")
    assert granted.status_code == 200 and granted.get_json()["status"] == "granted"

    # 2. ALLOW + зафіксований побічний ефект
    allowed = _send_marketing(op, uid)
    assert allowed.status_code == 200 and allowed.get_json()["status"] == "queued"
    assert _count(OutboxMessage, user_id=uid, action="marketing_email", status="queued") == 1

    # 3. REVOKE
    revoked = _revoke(user_a, uid, MKT, source="web")
    assert revoked.status_code == 200 and revoked.get_json()["status"] == "revoked"

    # 4. повторна дія: DENY, нових побічних ефектів немає
    blocked = _send_marketing(op, uid)
    assert blocked.status_code == 403
    assert blocked.get_json()["reason"] == "withdrawn"
    assert _count(OutboxMessage, user_id=uid) == 1                     # без змін


def test_gate_reasons_for_every_state(env):
    uid, gate = env["ids"]["a"], ConsentPolicyGate()
    user_a = client_for(env, "a")
    with flask_app.app_context():
        assert gate.check(uid, MKT).reason == "no_consent"
        assert gate.check(uid, "SOMETHING_ELSE").reason == "unknown_purpose"
    _grant(user_a, uid, MKT)
    with flask_app.app_context():
        assert gate.check(uid, MKT).allowed is True
    _revoke(user_a, uid, MKT)
    with flask_app.app_context():
        decision = gate.check(uid, MKT)
        assert (decision.allowed, decision.reason) == (False, "withdrawn")


# --- Ізоляція цілей ---------------------------------------------------------------

def test_consent_for_one_purpose_does_not_allow_another(env):
    uid, op, user_a = env["ids"]["a"], client_for(env, "op"), client_for(env, "a")
    _grant(user_a, uid, ANA)

    assert _send_marketing(op, uid).status_code == 403                  # MARKETING не дозволено
    assert user_a.post(f"/api/users/{uid}/analytics-event").status_code == 200   # ANALYTICS дозволено
    assert _count(OutboxMessage, user_id=uid, action="marketing_email") == 0
    assert _count(OutboxMessage, user_id=uid, action="analytics_event", status="recorded") == 1

    _grant(user_a, uid, MKT)
    _revoke(user_a, uid, ANA)
    assert _send_marketing(op, uid).status_code == 200                  # MARKETING працює
    denied = user_a.post(f"/api/users/{uid}/analytics-event")           # ANALYTICS заблоковано
    assert denied.status_code == 403 and denied.get_json()["reason"] == "withdrawn"
    assert _count(OutboxMessage, user_id=uid, action="analytics_event") == 1


# --- Докази та історія ------------------------------------------------------------

def test_evidence_policy_version_timestamps_source_and_history(env):
    uid, user_a = env["ids"]["a"], client_for(env, "a")
    _grant(user_a, uid, MKT, policy_version="2026-10-01", source="mobile")
    _revoke(user_a, uid, MKT, source="web")
    _grant(user_a, uid, MKT, source="web")

    body = user_a.get(f"/api/users/{uid}/consents").get_json()
    current = next(c for c in body["current"] if c["purpose"] == MKT)
    assert current["is_granted"] is True and current["policy_version"] == "2026-10-01"
    assert current["granted_at"].endswith("+00:00") and current["withdrawn_at"] is None
    assert current["updated_at"] and current["source"] == "web"
    assert body["current_policy_versions"][MKT] == "2026-10-01"

    history = [(e["action"], e["source"], e["policy_version"]) for e in body["history"]
               if e["purpose"] == MKT]
    assert history == [("GRANT", "mobile", "2026-10-01"), ("REVOKE", "web", "2026-10-01"),
                       ("GRANT", "web", "2026-10-01")]
    stamps = [e["occurred_at"] for e in body["history"]]
    assert stamps == sorted(stamps)
    with flask_app.app_context():
        assert all(e.correlation_id for e in ConsentEvent.query.filter_by(user_id=uid))


def test_revoke_keeps_evidence_of_what_was_accepted(env):
    uid, user_a = env["ids"]["a"], client_for(env, "a")
    _grant(user_a, uid, MKT)
    consent_row = _revoke(user_a, uid, MKT).get_json()["consent"]
    assert consent_row["is_granted"] is False
    assert consent_row["withdrawn_at"] and consent_row["granted_at"]     # обидві дати збережено
    assert consent_row["policy_version"] == "2026-10-01"                 # версія, яку було прийнято


# --- Ідемпотентність --------------------------------------------------------------

def test_commands_are_idempotent_and_do_not_create_contradictory_records(env):
    uid, user_a = env["ids"]["a"], client_for(env, "a")

    # REVOKE без жодної згоди: нічого не створюється
    r0 = _revoke(user_a, uid, MKT)
    assert r0.status_code == 200 and r0.get_json()["status"] == "no_consent"
    assert _count(UserConsent, user_id=uid) == 0 and _count(ConsentEvent, user_id=uid) == 0

    assert _grant(user_a, uid, MKT).get_json()["status"] == "granted"
    assert _grant(user_a, uid, MKT).get_json()["status"] == "already_granted"
    assert _count(ConsentEvent, user_id=uid, action="GRANT") == 1        # без дубля в історії

    first = _revoke(user_a, uid, MKT).get_json()
    second = _revoke(user_a, uid, MKT).get_json()
    assert first["status"] == "revoked" and second["status"] == "already_revoked"
    assert second["consent"]["withdrawn_at"] == first["consent"]["withdrawn_at"]   # не перезаписано
    assert _count(ConsentEvent, user_id=uid, action="REVOKE") == 1
    assert _count(UserConsent, user_id=uid, purpose=MKT) == 1            # один запис на мету


def test_regrant_after_revoke_restores_consent_with_new_timestamps(env):
    uid, user_a, op = env["ids"]["a"], client_for(env, "a"), client_for(env, "op")
    _grant(user_a, uid, MKT)
    _revoke(user_a, uid, MKT)
    again = _grant(user_a, uid, MKT).get_json()
    assert again["status"] == "granted" and again["consent"]["withdrawn_at"] is None
    assert _send_marketing(op, uid).status_code == 200


# --- Версія політики --------------------------------------------------------------

def test_wrong_policy_version_is_rejected_and_new_policy_invalidates_old_consent(env, monkeypatch):
    uid, user_a, op = env["ids"]["a"], client_for(env, "a"), client_for(env, "op")

    bad = _grant(user_a, uid, MKT, policy_version="1999-01-01")
    assert bad.status_code == 409
    assert bad.get_json() == {"error": "policy_version_outdated", "current_policy_version": "2026-10-01"}
    assert _count(UserConsent, user_id=uid) == 0

    _grant(user_a, uid, MKT)
    assert _send_marketing(op, uid).status_code == 200

    monkeypatch.setitem(consent.CURRENT_POLICY_VERSION, MKT, "2026-11-01")     # політику оновлено
    stale = _send_marketing(op, uid)
    assert stale.status_code == 403 and stale.get_json()["reason"] == "policy_version_outdated"
    assert _count(OutboxMessage, user_id=uid) == 1

    renewed = _grant(user_a, uid, MKT, policy_version="2026-11-01").get_json()
    assert renewed["status"] == "granted" or renewed["status"] == "renewed"
    assert renewed["consent"]["policy_version"] == "2026-11-01"
    assert _send_marketing(op, uid).status_code == 200


# --- Фонова обробка ---------------------------------------------------------------

def test_background_job_rechecks_consent_before_sending(env):
    uid, user_a, op = env["ids"]["a"], client_for(env, "a"), client_for(env, "op")
    _grant(user_a, uid, MKT)
    assert _send_marketing(op, uid).status_code == 200                  # поставлено в чергу
    _revoke(user_a, uid, MKT)                                           # згоду відкликано до відправки

    with flask_app.app_context():
        counts = dispatch_pending_messages()
    assert counts["sent"] == 0 and counts["blocked"] >= 1
    assert _count(OutboxMessage, user_id=uid, status="sent") == 0       # побічного ефекту немає
    assert _count(OutboxMessage, user_id=uid, status="blocked") == 1


def test_background_job_sends_when_consent_is_still_valid(env):
    uid, user_a, op = env["ids"]["a"], client_for(env, "a"), client_for(env, "op")
    _grant(user_a, uid, MKT)
    _send_marketing(op, uid)
    with flask_app.app_context():
        dispatch_pending_messages()
    assert _count(OutboxMessage, user_id=uid, status="sent") == 1


# --- Авторизація ------------------------------------------------------------------

def test_nobody_can_grant_or_revoke_consent_for_another_person(env):
    a, b = env["ids"]["a"], env["ids"]["b"]
    client_b, admin = client_for(env, "b"), client_for(env, "admin")

    for actor in (client_b, admin):
        res = _grant(actor, a, MKT)
        assert res.status_code == 403 and res.get_json() == {"error": "forbidden"}
        assert _revoke(actor, a, MKT).status_code == 403
    missing = _grant(client_b, a + 100000, MKT)
    assert missing.status_code == 403
    assert missing.get_data() == _grant(client_b, a, MKT).get_data()      # існування не розкривається
    assert _count(UserConsent, user_id=a) == 0

    anon = flask_app.test_client()
    assert _grant(anon, a, MKT).status_code == 401
    assert anon.get(f"/api/users/{a}/consents").status_code == 401


def test_listing_is_limited_to_subject_and_privileged_role(env):
    a = env["ids"]["a"]
    assert client_for(env, "b").get(f"/api/users/{a}/consents").status_code == 403
    assert client_for(env, "admin").get(f"/api/users/{a}/consents").status_code == 200
    missing = client_for(env, "admin").get(f"/api/users/{a + 100000}/consents")
    assert missing.status_code == 404


def test_input_validation(env):
    uid, user_a = env["ids"]["a"], client_for(env, "a")
    assert _grant(user_a, uid, "NO_SUCH_PURPOSE").get_json() == {"error": "unknown_purpose"}
    assert _grant(user_a, uid, MKT, source="carrier-pigeon").get_json() == {"error": "invalid_source"}
    assert _grant(user_a, uid, MKT, policy_version=5).get_json() == {"error": "invalid_policy_version"}
    # форма без JSON (міжсайтовий запит) не приймається
    form = user_a.post(f"/api/users/{uid}/consents/{MKT}/grant", data={"source": "web"})
    assert form.status_code == 400 and form.get_json() == {"error": "json_body_required"}
    assert _count(UserConsent, user_id=uid) == 0


def test_marketing_email_requires_staff_and_existing_subject(env):
    uid = env["ids"]["a"]
    _grant(client_for(env, "a"), uid, MKT)
    assert _send_marketing(client_for(env, "b"), uid).status_code == 403          # не персонал
    assert _send_marketing(client_for(env, "a"), uid).status_code == 403          # навіть сам суб'єкт
    assert _send_marketing(flask_app.test_client(), uid).status_code == 401
    assert _send_marketing(client_for(env, "op"), uid + 100000).status_code == 404
    assert _count(OutboxMessage, user_id=uid) == 0


# --- Згода не є універсальним прапорцем --------------------------------------------

def test_essential_functions_are_not_blocked_by_missing_or_revoked_consent(env):
    uid, user_a = env["ids"]["a"], client_for(env, "a")               # вхід працює без жодної згоди
    _grant(user_a, uid, MKT)
    _revoke(user_a, uid, MKT)

    assert user_a.get(f"/api/users/{uid}/personal-data").status_code == 200   # право доступу
    assert client_for(env, "a")                                                # повторний вхід
    assert user_a.get("/my_history").status_code == 200


# --- Експорт і анонімізація --------------------------------------------------------

def test_export_contains_consents_current_state_and_history(env):
    uid, user_a = env["ids"]["a"], client_for(env, "a")
    _grant(user_a, uid, MKT)
    _revoke(user_a, uid, MKT)
    section = user_a.get(f"/api/users/{uid}/personal-data").get_json()["consents"]

    assert section["available"] is True and section["time_zone"] == "UTC"
    assert section["source"] == ["user_consents", "user_consent_events"]
    assert [c["purpose"] for c in section["data"]["current"]] == [MKT]
    assert [e["action"] for e in section["data"]["history"]] == ["GRANT", "REVOKE"]


def test_erasure_withdraws_consents_and_keeps_evidence_without_pii(env):
    uid, user_a, op = env["ids"]["a"], client_for(env, "a"), client_for(env, "op")
    _grant(user_a, uid, MKT)
    _grant(user_a, uid, ANA)
    admin = client_for(env, "admin")
    res = admin.post(f"/api/users/{uid}/anonymize", json={"confirm": True})
    assert res.status_code == 200 and res.get_json()["summary"]["consents_withdrawn"] == 2

    assert _send_marketing(op, uid).status_code == 403                # згоди відкликано
    with flask_app.app_context():
        rows = UserConsent.query.filter_by(user_id=uid).all()
        events = ConsentEvent.query.filter_by(user_id=uid).order_by(ConsentEvent.id).all()
        assert len(rows) == 2 and all(not r.is_granted for r in rows)
        assert [e.action for e in events] == ["GRANT", "GRANT", "REVOKE", "REVOKE"]
        assert {e.source for e in events if e.action == "REVOKE"} == {"erasure"}
        dump = json.dumps([[str(getattr(r, c.name)) for c in r.__table__.columns]
                           for r in rows + events])
    assert env["emails"]["a"] not in dump and env["names"]["a"] not in dump    # доказ без PII


# --- Журнали ---------------------------------------------------------------------

class _RawCapture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.lines = []

    def emit(self, record):
        extras = {k: v for k, v in record.__dict__.items()
                  if k not in logging.makeLogRecord({}).__dict__}
        self.lines.append((record.name, record.getMessage(), extras))


def test_consent_operations_do_not_log_personal_data(env):
    root = logging.getLogger()
    capture = _RawCapture()
    root.handlers.insert(0, capture)
    try:
        uid, user_a, op = env["ids"]["a"], client_for(env, "a"), client_for(env, "op")
        _grant(user_a, uid, MKT)
        _send_marketing(op, uid)
        _revoke(user_a, uid, MKT)
        _send_marketing(op, uid)
    finally:
        root.handlers.remove(capture)
    text = json.dumps(capture.lines, ensure_ascii=False, default=str)
    for pii in (env["emails"]["a"], env["names"]["a"], PASSWORDS["a"]):
        assert pii not in text
    outcomes = [(e.get("operation"), e.get("outcome")) for name, _, e in capture.lines
                if name == "security" and str(e.get("operation", "")).startswith(
                    ("consent_", "marketing_email"))]
    assert ("consent_grant", "success") in outcomes and ("consent_revoke", "success") in outcomes
    assert ("marketing_email", "success") in outcomes and ("marketing_email", "denied") in outcomes
