import base64
import time

import jwt
import pytest
from fastapi.testclient import TestClient

from fog.app import app
from fog.database import Base, SessionLocal, engine
from fog.registration import public_key_thumbprint
from fog.settings import settings
from devices.device import SimulatedDevice

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


def _authenticated_device_payload(sim: SimulatedDevice, device_type="temperature_sensor", role="sensor"):
    return {
        "device_id": sim.device_id,
        "did": sim.did,
        "public_key": sim.public_key_pem,
        "public_key_thumbprint": public_key_thumbprint(sim.public_key_pem),
        "device_type": device_type,
        "role": role,
        "zone": "zone-1",
        "authentication_complete": True,
        "proof_of_possession_verified": True,
        "status": "PENDING",
    }


def _issue_token(sim: SimulatedDevice, **kwargs):
    resp = client.post("/token/issue", json={"device": _authenticated_device_payload(sim, **kwargs)})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _signed_request(sim: SimulatedDevice, token: str, resource, operation, nonce, timestamp=None, body_hash="deadbeef"):
    jti = jwt.decode(
        token, settings.jwt_secret, algorithms=[settings.jwt_algorithm], options={"verify_exp": False}
    )["jti"]
    ts = timestamp if timestamp is not None else int(time.time())
    message = f"{sim.did}|{resource}|{operation}|{body_hash}|{nonce}|{ts}|{jti}".encode("utf-8")
    signature = sim.sign(message)
    return {
        "token": token,
        "did": sim.did,
        "resource": resource,
        "operation": operation,
        "body_hash": body_hash,
        "nonce": nonce,
        "timestamp": ts,
        "signature": signature,
    }


def test_token_issuance_requires_completed_authentication():
    sim = SimulatedDevice("dev-1", "temperature_sensor")
    payload = _authenticated_device_payload(sim)
    payload["proof_of_possession_verified"] = False
    resp = client.post("/token/issue", json={"device": payload})
    assert resp.status_code == 401


def test_token_issuance_queues_device_for_next_batch():
    sim = SimulatedDevice("dev-2", "temperature_sensor")
    _issue_token(sim)
    queued = client.get("/batch/queue").json()
    assert any(item["did"] == sim.did for item in queued)


def test_valid_provisional_request_is_allowed():
    sim = SimulatedDevice("dev-3", "temperature_sensor")
    token = _issue_token(sim)
    request = _signed_request(sim, token, "temperature_readings", "WRITE", nonce="n-1")
    resp = client.post("/access/temporary", json=request)
    body = resp.json()
    assert body["decision"] == "ALLOW"
    assert body["code"] == "ACCESS_ALLOWED"


def test_provisional_policy_denies_out_of_scope_operation():
    sim = SimulatedDevice("dev-4", "temperature_sensor")
    token = _issue_token(sim)
    request = _signed_request(sim, token, "production_line", "STOP", nonce="n-2")
    resp = client.post("/access/temporary", json=request)
    body = resp.json()
    assert body["decision"] == "DENY"
    assert body["code"] == "POLICY_DENIED"


def test_attack_replay_of_exact_request_is_rejected_via_nonce_reuse():
    sim = SimulatedDevice("dev-5", "temperature_sensor")
    token = _issue_token(sim)
    request = _signed_request(sim, token, "temperature_readings", "WRITE", nonce="reused-nonce")

    first = client.post("/access/temporary", json=request).json()
    assert first["decision"] == "ALLOW"

    replay = client.post("/access/temporary", json=request).json()
    assert replay["decision"] == "DENY"
    assert replay["code"] == "NONCE_REUSED"


def test_attack_stolen_token_used_from_another_device_is_rejected():
    victim = SimulatedDevice("dev-6", "temperature_sensor")
    attacker = SimulatedDevice("dev-7", "temperature_sensor")
    token = _issue_token(victim)
    # attacker copies the still-valid token but signs the request with its OWN key
    request = _signed_request(victim, token, "temperature_readings", "WRITE", nonce="n-3")
    request["signature"] = attacker.sign(
        f"{victim.did}|temperature_readings|WRITE|deadbeef|n-3|{request['timestamp']}|"
        f"{jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])['jti']}".encode("utf-8")
    )
    resp = client.post("/access/temporary", json=request).json()
    assert resp["decision"] == "DENY"
    assert resp["code"] == "REQUEST_SIGNATURE_INVALID"


def test_attack_tampered_signature_is_rejected():
    sim = SimulatedDevice("dev-8", "temperature_sensor")
    token = _issue_token(sim)
    request = _signed_request(sim, token, "temperature_readings", "WRITE", nonce="n-4")
    tampered = base64.b64decode(request["signature"])
    tampered = bytes([tampered[0] ^ 0xFF]) + tampered[1:]
    request["signature"] = base64.b64encode(tampered).decode("ascii")
    resp = client.post("/access/temporary", json=request).json()
    assert resp["decision"] == "DENY"
    assert resp["code"] == "REQUEST_SIGNATURE_INVALID"


def test_attack_expired_token_is_rejected():
    sim = SimulatedDevice("dev-9", "temperature_sensor")
    token = _issue_token(sim)
    # forge an already-expired token with the same secret to simulate TTL elapsing
    payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    payload["exp"] = int(time.time()) - 10
    expired_token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    request = _signed_request(sim, expired_token, "temperature_readings", "WRITE", nonce="n-5")
    resp = client.post("/access/temporary", json=request).json()
    assert resp["decision"] == "DENY"
    assert resp["code"] == "TOKEN_EXPIRED"


def test_attack_revoked_token_is_rejected():
    sim = SimulatedDevice("dev-10", "temperature_sensor")
    token = _issue_token(sim)
    jti = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])["jti"]

    revoke_resp = client.post(f"/tokens/{jti}/revoke", json={"reason": "compromised"})
    assert revoke_resp.status_code == 200

    request = _signed_request(sim, token, "temperature_readings", "WRITE", nonce="n-6")
    resp = client.post("/access/temporary", json=request).json()
    assert resp["decision"] == "DENY"
    assert resp["code"] == "TOKEN_REVOKED"


def test_stale_timestamp_is_rejected():
    sim = SimulatedDevice("dev-11", "temperature_sensor")
    token = _issue_token(sim)
    old_ts = int(time.time()) - 3600
    request = _signed_request(sim, token, "temperature_readings", "WRITE", nonce="n-7", timestamp=old_ts)
    resp = client.post("/access/temporary", json=request).json()
    assert resp["decision"] == "DENY"
    assert resp["code"] == "STALE_TIMESTAMP"
