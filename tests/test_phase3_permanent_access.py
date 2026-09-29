import time

from fastapi.testclient import TestClient

from fog.app import app
from fog.database import Base, engine
from fog.registration import public_key_thumbprint
from devices.device import SimulatedDevice

import pytest

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


def _register_and_finalize(devices_with_types):
    """Register N devices with the fog's local record (via /token/issue, which
    upserts fog/models.Device) then finalize one epoch containing all of them.
    Returns {did: {"epoch_id", "leaf", "siblings"}}.
    """
    sims = []
    for sim, device_type, role in devices_with_types:
        payload = {
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
        resp = client.post("/token/issue", json={"device": payload})
        assert resp.status_code == 200, resp.text
        sims.append(sim)

    finalize_resp = client.post(
    "/batch/finalize"
)
    assert finalize_resp.status_code == 200, finalize_resp.text
    return finalize_resp.json()


def _signed_permanent_request(sim, proof_info, resource, operation, nonce, timestamp=None, body_hash="deadbeef"):
    ts = timestamp if timestamp is not None else int(time.time())
    message = f"{sim.did}|{resource}|{operation}|{body_hash}|{nonce}|{ts}|".encode("utf-8")
    signature = sim.sign(message)
    return {
        "did": sim.did,
        "public_key": sim.public_key_pem,
        "epoch_id": proof_info["epoch_id"],
        "proof": {"epoch_id": proof_info["epoch_id"], "leaf": proof_info["leaf"], "siblings": proof_info["siblings"]},
        "resource": resource,
        "operation": operation,
        "body_hash": body_hash,
        "nonce": nonce,
        "timestamp": ts,
        "signature": signature,
    }


def test_valid_permanent_request_is_allowed():
    sim = SimulatedDevice("perm-1", "temperature_sensor")
    proofs = _register_and_finalize([(sim, "temperature_sensor", "sensor")])
    request = _signed_permanent_request(sim, proofs["proofs"][sim.did], "temperature_readings", "READ", nonce="p-1")
    resp = client.post("/access/permanent", json=request).json()
    assert resp["decision"] == "ALLOW"
    assert resp["code"] == "ACCESS_ALLOWED"


def test_rbac_denies_operation_outside_device_type_policy():
    sim = SimulatedDevice("perm-2", "temperature_sensor")
    proofs = _register_and_finalize([(sim, "temperature_sensor", "sensor")])
    # a temperature sensor may never STOP a production line
    request = _signed_permanent_request(sim, proofs["proofs"][sim.did], "motor", "STOP", nonce="p-2")
    resp = client.post("/access/permanent", json=request).json()
    assert resp["decision"] == "DENY"
    assert resp["code"] == "POLICY_DENIED"


def test_rbac_allows_role_appropriate_operation_for_actuator():
    sim = SimulatedDevice("perm-3", "motor_controller")
    proofs = _register_and_finalize([(sim, "motor_controller", "actuator")])
    request = _signed_permanent_request(sim, proofs["proofs"][sim.did], "motor", "START", nonce="p-3")
    resp = client.post("/access/permanent", json=request).json()
    assert resp["decision"] == "ALLOW"


def test_attack_tampered_proof_sibling_is_rejected():
    sim = SimulatedDevice("perm-4", "temperature_sensor")
    other = SimulatedDevice("perm-5", "pressure_sensor")
    proofs = _register_and_finalize(
        [(sim, "temperature_sensor", "sensor"), (other, "pressure_sensor", "sensor")]
    )
    request = _signed_permanent_request(sim, proofs["proofs"][sim.did], "temperature_readings", "READ", nonce="p-4")
    # flip a bit in the first sibling hash
    tampered = bytearray(bytes.fromhex(request["proof"]["siblings"][0]["hash"]))
    tampered[0] ^= 0xFF
    request["proof"]["siblings"][0]["hash"] = bytes(tampered).hex()
    resp = client.post("/access/permanent", json=request).json()
    assert resp["decision"] == "DENY"
    assert resp["code"] == "INCLUSION_PROOF_INVALID"


def test_attack_tampered_public_key_is_rejected():
    sim = SimulatedDevice("perm-6", "temperature_sensor")
    proofs = _register_and_finalize([(sim, "temperature_sensor", "sensor")])
    attacker = SimulatedDevice("perm-7", "temperature_sensor")
    request = _signed_permanent_request(sim, proofs["proofs"][sim.did], "temperature_readings", "READ", nonce="p-5")
    request["public_key"] = attacker.public_key_pem  # swap in a different key
    resp = client.post("/access/permanent", json=request).json()
    assert resp["decision"] == "DENY"
    assert resp["code"] == "INCLUSION_PROOF_INVALID"


def test_attack_replay_is_rejected_via_nonce_reuse():
    sim = SimulatedDevice("perm-8", "temperature_sensor")
    proofs = _register_and_finalize([(sim, "temperature_sensor", "sensor")])
    request = _signed_permanent_request(sim, proofs["proofs"][sim.did], "temperature_readings", "READ", nonce="p-6")
    first = client.post("/access/permanent", json=request).json()
    assert first["decision"] == "ALLOW"
    replay = client.post("/access/permanent", json=request).json()
    assert replay["decision"] == "DENY"
    assert replay["code"] == "NONCE_REUSED"


def test_attack_forged_signature_is_rejected():
    sim = SimulatedDevice("perm-9", "temperature_sensor")
    proofs = _register_and_finalize([(sim, "temperature_sensor", "sensor")])
    request = _signed_permanent_request(sim, proofs["proofs"][sim.did], "temperature_readings", "READ", nonce="p-7")
    request["signature"] = request["signature"][:-4] + ("AAAA" if request["signature"][-4:] != "AAAA" else "BBBB")
    resp = client.post("/access/permanent", json=request).json()
    assert resp["decision"] == "DENY"
    assert resp["code"] == "REQUEST_SIGNATURE_INVALID"


def test_revoked_device_denied_permanent_access():
    sim = SimulatedDevice("perm-10", "temperature_sensor")
    proofs = _register_and_finalize([(sim, "temperature_sensor", "sensor")])
    revoke = client.post(f"/devices/{sim.did}/revoke", json={"reason": "compromised"})
    assert revoke.status_code == 200
    assert revoke.json()["status"] == "REVOKED"

    # The device's OLD, still-structurally-valid inclusion proof must now be
    # rejected -- this is the "old historical proof vs current authorization
    # status" distinction the assignment calls for.
    request = _signed_permanent_request(sim, proofs["proofs"][sim.did], "temperature_readings", "READ", nonce="p-8")
    resp = client.post("/access/permanent", json=request).json()
    assert resp["decision"] == "DENY"
    assert resp["code"] == "DEVICE_REVOKED"


def test_unknown_epoch_is_rejected():
    sim = SimulatedDevice("perm-11", "temperature_sensor")
    proofs = _register_and_finalize([(sim, "temperature_sensor", "sensor")])
    request = _signed_permanent_request(sim, proofs["proofs"][sim.did], "temperature_readings", "READ", nonce="p-9")
    request["epoch_id"] = 9999
    request["proof"]["epoch_id"] = 9999
    resp = client.post("/access/permanent", json=request).json()
    assert resp["decision"] == "DENY"
    assert resp["code"] == "EPOCH_NOT_FOUND"


def test_stale_timestamp_rejected_on_permanent_access():
    sim = SimulatedDevice("perm-12", "temperature_sensor")
    proofs = _register_and_finalize([(sim, "temperature_sensor", "sensor")])
    old_ts = int(time.time()) - 3600
    request = _signed_permanent_request(
        sim, proofs["proofs"][sim.did], "temperature_readings", "READ", nonce="p-10", timestamp=old_ts
    )
    resp = client.post("/access/permanent", json=request).json()
    assert resp["decision"] == "DENY"
    assert resp["code"] == "STALE_TIMESTAMP"
