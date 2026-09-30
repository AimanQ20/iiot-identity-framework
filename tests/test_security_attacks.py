"""Four assignment-level attack demonstrations against the integrated API."""

import time

import jwt
from fastapi.testclient import TestClient

from devices.device import SimulatedDevice
from fog.app import app
from fog.database import SessionLocal
from fog.models import Device
from fog.registration import public_key_thumbprint
from fog.settings import settings


client = TestClient(app)


def device_payload(device: SimulatedDevice) -> dict:
    return {
        "device_id": device.device_id,
        "did": device.did,
        "public_key": device.public_key_pem,
        "public_key_thumbprint": public_key_thumbprint(device.public_key_pem),
        "device_type": device.device_type,
        "role": device.role,
        "zone": device.zone,
        "authentication_complete": True,
        "proof_of_possession_verified": True,
        "status": "PENDING",
    }


def issue(device: SimulatedDevice) -> str:
    payload = device_payload(device)
    db = SessionLocal()
    try:
        db.add(Device(
            device_id=payload["device_id"], did=payload["did"],
            public_key=payload["public_key"],
            public_key_thumbprint=payload["public_key_thumbprint"],
            device_type=payload["device_type"], role=payload["role"],
            zone=payload["zone"], status="PENDING",
            authentication_complete=True, pop_verified=True,
        ))
        db.commit()
    finally:
        db.close()
    response = client.post("/token/issue", json={"device": payload})
    assert response.status_code == 200
    return response.json()["access_token"]


def temporary_request(device: SimulatedDevice, token: str, nonce: str) -> dict:
    jti = jwt.decode(
        token, settings.jwt_secret, algorithms=[settings.jwt_algorithm],
        options={"verify_exp": False},
    )["jti"]
    return {
        "token": token,
        **device.build_signed_request(
            resource="temperature_readings",
            operation="WRITE",
            body_hash="security-evaluation",
            nonce=nonce,
            timestamp=int(time.time()),
            token_jti=jti,
        ),
    }


def permanent_request(device: SimulatedDevice, proof: dict, nonce: str) -> dict:
    return {
        "did": device.did,
        "public_key": device.public_key_pem,
        "epoch_id": proof["epoch_id"],
        "proof": {
            "epoch_id": proof["epoch_id"],
            "leaf": proof["leaf"],
            "siblings": proof["siblings"],
        },
        **device.build_signed_request(
            resource="temperature_readings",
            operation="READ",
            body_hash="security-evaluation",
            nonce=nonce,
            timestamp=int(time.time()),
        ),
    }


def test_attack_1_exact_request_replay_is_blocked():
    device = SimulatedDevice("SEC-REPLAY", "temperature_sensor")
    token = issue(device)
    request = temporary_request(device, token, "attack-replay-nonce")
    assert client.post("/access/temporary", json=request).json()["decision"] == "ALLOW"
    replay = client.post("/access/temporary", json=request).json()
    assert replay["decision"] == "DENY"
    assert replay["code"] == "NONCE_REUSED"


def test_attack_2_tampered_merkle_proof_is_blocked():
    device = SimulatedDevice("SEC-PROOF", "temperature_sensor")
    other = SimulatedDevice("SEC-PROOF-OTHER", "pressure_sensor")
    issue(device)
    issue(other)
    batch = client.post("/batch/finalize").json()
    request = permanent_request(device, batch["proofs"][device.did], "attack-proof-nonce")
    request["proof"]["siblings"][0]["hash"] = "00" * 32
    decision = client.post("/access/permanent", json=request).json()
    assert decision["decision"] == "DENY"
    assert decision["code"] == "INCLUSION_PROOF_INVALID"


def test_attack_3_stolen_token_without_private_key_is_blocked():
    victim = SimulatedDevice("SEC-VICTIM", "temperature_sensor")
    attacker = SimulatedDevice("SEC-ATTACKER", "temperature_sensor")
    token = issue(victim)
    request = temporary_request(victim, token, "attack-stolen-token")
    # Attacker replaces the victim's valid signature with one from its own key.
    jti = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])["jti"]
    forged = attacker.build_signed_request(
        resource=request["resource"], operation=request["operation"],
        body_hash=request["body_hash"], nonce=request["nonce"],
        timestamp=request["timestamp"], token_jti=jti,
    )
    request["signature"] = forged["signature"]
    decision = client.post("/access/temporary", json=request).json()
    assert decision["decision"] == "DENY"
    assert decision["code"] == "REQUEST_SIGNATURE_INVALID"


def test_attack_4_revoked_token_reuse_is_blocked():
    device = SimulatedDevice("SEC-REVOKED", "temperature_sensor")
    token = issue(device)
    jti = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])["jti"]
    assert client.post(f"/tokens/{jti}/revoke", json={"reason": "security evaluation"}).status_code == 200
    decision = client.post(
        "/access/temporary",
        json=temporary_request(device, token, "attack-revoked-token"),
    ).json()
    assert decision["decision"] == "DENY"
    assert decision["code"] == "TOKEN_REVOKED"
