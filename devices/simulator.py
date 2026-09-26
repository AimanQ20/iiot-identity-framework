"""Automatic end-to-end Phase 1 device simulator.

Start the FastAPI server first:

    python -m uvicorn fog.app:app --reload

Then run:

    python -m devices.simulator
"""

import json
import sys

import httpx

from devices.device import SimulatedDevice


API_URL = "http://127.0.0.1:8000"


DEVICE_PROFILES = [
    {
        "device_id": "TEMP-001",
        "device_type": "temperature_sensor",
        "role": "sensor",
        "psk": "temp-device-secret-001",
    },
    {
        "device_id": "TEMP-002",
        "device_type": "temperature_sensor",
        "role": "sensor",
        "psk": "temp-device-secret-002",
    },
    {
        "device_id": "PRESS-001",
        "device_type": "pressure_sensor",
        "role": "sensor",
        "psk": "pressure-device-secret-001",
    },
    {
        "device_id": "CAM-001",
        "device_type": "camera",
        "role": "monitor",
        "psk": "camera-device-secret-001",
    },
    {
        "device_id": "VALVE-001",
        "device_type": "valve_controller",
        "role": "actuator",
        "psk": "valve-device-secret-001",
    },
    {
        "device_id": "MOTOR-001",
        "device_type": "motor_controller",
        "role": "actuator",
        "psk": "motor-device-secret-001",
    },
    {
        "device_id": "METER-001",
        "device_type": "smart_meter",
        "role": "sensor",
        "psk": "meter-device-secret-001",
    },
]


def ensure_server_is_running(client: httpx.Client) -> None:
    try:
        response = client.get(f"{API_URL}/health")
        response.raise_for_status()
    except httpx.HTTPError as exc:
        print("Fog server is not running.")
        print(
            "Start it using: "
            "python -m uvicorn fog.app:app --reload"
        )
        raise SystemExit(1) from exc


def register_device(
    client: httpx.Client,
    device: SimulatedDevice,
) -> dict:
    print(f"\nRegistering {device.device_id}")
    print("-" * 60)

    # Step 1: Device requests a PSK authentication nonce.
    auth_response = client.post(
        f"{API_URL}/auth/challenge",
        json={
            "device_id": device.device_id,
        },
    )
    auth_response.raise_for_status()

    auth_data = auth_response.json()
    auth_nonce = auth_data["nonce"]

    print(f"[1] Authentication nonce received: {auth_nonce[:20]}...")

    # Step 2: Device calculates HMAC using its PSK.
    auth_hmac = device.create_psk_response(auth_nonce)

    print(f"[2] PSK response generated: {auth_hmac[:20]}...")

    # Step 3: Send public identity and PSK response to fog.
    begin_response = client.post(
        f"{API_URL}/registration/begin",
        json={
            "device_id": device.device_id,
            "auth_nonce": auth_nonce,
            "auth_hmac": auth_hmac,
            "did": device.did,
            "public_key": device.public_key_pem,
            "device_type": device.device_type,
            "role": device.role,
            "zone": device.zone,
        },
    )
    begin_response.raise_for_status()

    begin_data = begin_response.json()
    registration_id = begin_data["registration_id"]
    pop_challenge = begin_data["challenge"]

    print("[3] PSK authentication successful")
    print(
        f"[4] Proof-of-possession challenge received: "
        f"{pop_challenge[:20]}..."
    )

    # Step 4: Sign fresh challenge using device private key.
    pop_signature = device.sign_challenge(pop_challenge)

    print("[5] Challenge signed using ECC private key")

    # Step 5: Complete registration.
    complete_response = client.post(
        f"{API_URL}/registration/complete",
        json={
            "registration_id": registration_id,
            "signature": pop_signature,
        },
    )
    complete_response.raise_for_status()

    result = complete_response.json()

    print("[6] Proof-of-possession verified")
    print(f"[7] DID: {result['device']['did']}")
    print(f"[8] Leaf: {result['leaf']}")
    print(f"[9] Status: {result['device']['status']}")

    return result


def finalize_batch(client: httpx.Client) -> dict:
    print("\nFinalizing registration batch")
    print("=" * 60)

    response = client.post(f"{API_URL}/batch/finalize")
    response.raise_for_status()

    result = response.json()

    print(f"Epoch: {result['epoch_id']}")
    print(f"Devices included: {result['device_count']}")
    print(f"Merkle root: {result['merkle_root']}")
    print(f"Proofs generated: {len(result['proofs'])}")

    return result


def main():
    devices: list[SimulatedDevice] = []

    with httpx.Client(timeout=30.0) as client:
        ensure_server_is_running(client)

        for profile in DEVICE_PROFILES:
            device = SimulatedDevice(**profile)
            devices.append(device)

            try:
                register_device(client, device)
            except httpx.HTTPStatusError as exc:
                print(
                    f"Registration failed for {device.device_id}: "
                    f"{exc.response.text}"
                )
                sys.exit(1)

        try:
            epoch = finalize_batch(client)
        except httpx.HTTPStatusError as exc:
            print(f"Batch finalization failed: {exc.response.text}")
            sys.exit(1)

        with open(
            "data/latest_demo_epoch.json",
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(epoch, file, indent=2)

        print("\nPhase 1 simulation completed successfully.")
        print(
            "Results saved to data/latest_demo_epoch.json"
        )


if __name__ == "__main__":
    main()