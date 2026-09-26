import base64
import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from devices.device import SimulatedDevice
from fog.registration import (
    create_device_leaf,
    derive_did,
    issue_authentication_challenge,
    verify_pop_signature,
    verify_psk_response,
)


def test_correct_psk_response_passes():
    device = SimulatedDevice(
        device_id="TEMP-001",
        device_type="temperature_sensor",
        psk="temp-device-secret-001",
    )

    nonce, _ = issue_authentication_challenge(
        device.device_id
    )

    response = device.create_psk_response(nonce)

    assert verify_psk_response(
        device.device_id,
        nonce,
        response,
    )


def test_incorrect_psk_response_fails():
    nonce, _ = issue_authentication_challenge("TEMP-002")

    wrong_response = hmac.new(
        b"wrong-secret",
        f"TEMP-002|{nonce}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    assert not verify_psk_response(
        "TEMP-002",
        nonce,
        wrong_response,
    )


def test_authentication_nonce_cannot_be_replayed():
    device = SimulatedDevice(
        device_id="PRESS-001",
        device_type="pressure_sensor",
        psk="pressure-device-secret-001",
    )

    nonce, _ = issue_authentication_challenge(
        device.device_id
    )

    response = device.create_psk_response(nonce)

    assert verify_psk_response(
        device.device_id,
        nonce,
        response,
    )

    assert not verify_psk_response(
        device.device_id,
        nonce,
        response,
    )


def test_valid_proof_of_possession_passes():
    device = SimulatedDevice(
        device_id="CAM-001",
        device_type="camera",
        psk="camera-device-secret-001",
    )

    challenge = "fresh-fog-challenge"
    signature = device.sign_challenge(challenge)

    assert verify_pop_signature(
        device.public_key_pem,
        challenge,
        signature,
    )


def test_signature_from_different_device_fails():
    real_device = SimulatedDevice(
        device_id="VALVE-001",
        device_type="valve_controller",
        psk="valve-device-secret-001",
    )

    attacker = SimulatedDevice(
        device_id="ATTACKER-001",
        device_type="temperature_sensor",
        psk="attacker-device-secret-001",
    )

    challenge = "challenge-for-real-device"
    attacker_signature = attacker.sign_challenge(challenge)

    assert not verify_pop_signature(
        real_device.public_key_pem,
        challenge,
        attacker_signature,
    )


def test_did_is_derived_from_public_key():
    device = SimulatedDevice(
        device_id="METER-001",
        device_type="smart_meter",
        psk="meter-device-secret-001",
    )

    assert derive_did(device.public_key_pem) == device.did


def test_device_leaf_is_deterministic():
    device = SimulatedDevice(
        device_id="MOTOR-001",
        device_type="motor_controller",
        psk="motor-device-secret-001",
    )

    first_leaf = create_device_leaf(
        device.did,
        device.public_key_pem,
    )

    second_leaf = create_device_leaf(
        device.did,
        device.public_key_pem,
    )

    assert first_leaf == second_leaf
    assert len(first_leaf) == 32