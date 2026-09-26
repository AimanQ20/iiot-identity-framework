from fastapi.testclient import TestClient

from fog.app import app
from fog.authorization import authorize
from fog.merkle import build_merkle_root


client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_merkle_root_is_deterministic_after_sorting():
    leaves = [bytes.fromhex("02" * 32), bytes.fromhex("01" * 32)]
    assert build_merkle_root(leaves) == build_merkle_root(list(reversed(leaves)))


def test_provisional_policy_is_limited():
    assert authorize("temperature_sensor", "temperature_readings", "WRITE", True)
    assert not authorize("temperature_sensor", "production_line", "STOP", True)

