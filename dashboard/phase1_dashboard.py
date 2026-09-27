"""Complete Phase 1 Streamlit dashboard.

Run the API:
    python -m uvicorn fog.app:app --reload

Run the dashboard:
    python -m streamlit run dashboard/phase1_dashboard.py
"""

import time
from typing import Any

import httpx
import pandas as pd
import streamlit as st

from devices.device import SimulatedDevice


API_URL = "http://127.0.0.1:8000"


DEVICE_PROFILES = {
    "Temperature Sensor 1": {
        "device_id": "TEMP-001",
        "device_type": "temperature_sensor",
        "role": "sensor",
        "psk": "temp-device-secret-001",
    },
    "Temperature Sensor 2": {
        "device_id": "TEMP-002",
        "device_type": "temperature_sensor",
        "role": "sensor",
        "psk": "temp-device-secret-002",
    },
    "Pressure Sensor": {
        "device_id": "PRESS-001",
        "device_type": "pressure_sensor",
        "role": "sensor",
        "psk": "pressure-device-secret-001",
    },
    "Camera": {
        "device_id": "CAM-001",
        "device_type": "camera",
        "role": "monitor",
        "psk": "camera-device-secret-001",
    },
    "Valve Controller": {
        "device_id": "VALVE-001",
        "device_type": "valve_controller",
        "role": "actuator",
        "psk": "valve-device-secret-001",
    },
    "Motor Controller": {
        "device_id": "MOTOR-001",
        "device_type": "motor_controller",
        "role": "actuator",
        "psk": "motor-device-secret-001",
    },
    "Smart Meter": {
        "device_id": "METER-001",
        "device_type": "smart_meter",
        "role": "sensor",
        "psk": "meter-device-secret-001",
    },
}


st.set_page_config(
    page_title="IIoT Identity Framework",
    page_icon="🔐",
    layout="wide",
)


# -------------------------------------------------------------------
# Session state
# -------------------------------------------------------------------


if "simulated_devices" not in st.session_state:
    st.session_state.simulated_devices = {}

if "logs" not in st.session_state:
    st.session_state.logs = []

if "latest_proof" not in st.session_state:
    st.session_state.latest_proof = None

if "latest_proof_device" not in st.session_state:
    st.session_state.latest_proof_device = None


# -------------------------------------------------------------------
# General helpers
# -------------------------------------------------------------------


def add_log(
    message: str,
    category: str = "INFO",
) -> None:
    timestamp = time.strftime("%H:%M:%S")

    st.session_state.logs.append(
        {
            "time": timestamp,
            "category": category,
            "message": message,
        }
    )


def api_request(
    method: str,
    path: str,
    **kwargs: Any,
):
    """Send a request to the FastAPI fog node."""

    try:
        response = httpx.request(
            method,
            f"{API_URL}{path}",
            timeout=30.0,
            **kwargs,
        )

    except httpx.RequestError:
        st.error(
            "The fog API is not running.\n\n"
            "Start it in another terminal using:\n\n"
            "`python -m uvicorn fog.app:app --reload`"
        )
        return None

    if response.status_code >= 400:
        try:
            error_body = response.json()
        except ValueError:
            error_body = response.text

        st.error(
            f"API request failed ({response.status_code}): "
            f"{error_body}"
        )

        return None

    return response.json()


def get_devices() -> list[dict]:
    response = api_request(
        "GET",
        "/devices",
    )

    return response if response is not None else []


def get_epochs() -> list[dict]:
    response = api_request(
        "GET",
        "/epochs",
    )

    return response if response is not None else []


def get_device_label(device: dict) -> str:
    return (
        f"{device['device_id']} — "
        f"{device['device_type']} — "
        f"{device['status']}"
    )


# -------------------------------------------------------------------
# Registration
# -------------------------------------------------------------------


def register_device(profile: dict) -> bool:
    """Perform the complete Phase 1 onboarding protocol."""

    device = SimulatedDevice(**profile)

    add_log(
        f"{device.device_id}: requesting authentication nonce"
    )

    authentication = api_request(
        "POST",
        "/auth/challenge",
        json={
            "device_id": device.device_id,
        },
    )

    if authentication is None:
        add_log(
            f"{device.device_id}: authentication challenge failed",
            "ERROR",
        )
        return False

    auth_nonce = authentication["nonce"]

    add_log(
        f"{device.device_id}: fresh authentication nonce received",
        "PASS",
    )

    auth_hmac = device.create_psk_response(
        auth_nonce
    )

    add_log(
        f"{device.device_id}: HMAC-SHA256 response generated"
    )

    registration_start = api_request(
        "POST",
        "/registration/begin",
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

    if registration_start is None:
        add_log(
            f"{device.device_id}: PSK authentication failed",
            "DENY",
        )
        return False

    add_log(
        f"{device.device_id}: PSK authentication passed",
        "PASS",
    )

    pop_challenge = registration_start[
        "challenge"
    ]

    pop_signature = device.sign_challenge(
        pop_challenge
    )

    add_log(
        f"{device.device_id}: PoP challenge signed using ECC key"
    )

    registration_result = api_request(
        "POST",
        "/registration/complete",
        json={
            "registration_id": registration_start[
                "registration_id"
            ],
            "signature": pop_signature,
        },
    )

    if registration_result is None:
        add_log(
            f"{device.device_id}: proof-of-possession failed",
            "DENY",
        )
        return False

    st.session_state.simulated_devices[
        device.device_id
    ] = device

    add_log(
        f"{device.device_id}: proof-of-possession verified",
        "PASS",
    )

    add_log(
        f"{device.device_id}: added to pending batch",
        "PASS",
    )

    st.success(
        f"{device.device_id} registered successfully"
    )

    with st.expander(
        f"Registration details — {device.device_id}",
        expanded=True,
    ):
        st.write("**DID**")
        st.code(
            registration_result["device"]["did"],
            language=None,
        )

        st.write("**Device leaf**")
        st.code(
            registration_result["leaf"],
            language=None,
        )

        st.write(
            f"**Status:** "
            f"{registration_result['device']['status']}"
        )

    return True


# -------------------------------------------------------------------
# Interface header
# -------------------------------------------------------------------


st.title("Single-Zone IIoT Identity Framework")

st.caption(
    "Decentralized device registration, proof-of-possession, "
    "Merkle membership, revocation and identity verification"
)

health = api_request(
    "GET",
    "/health",
)

if health is None:
    st.stop()

st.success(
    f"Fog node online — {health['zone']}"
)


registered_devices = get_devices()
trusted_epochs = get_epochs()

pending_count = sum(
    device["status"] == "PENDING"
    for device in registered_devices
)

active_count = sum(
    device["status"] == "ACTIVE"
    for device in registered_devices
)

revoked_count = sum(
    device["status"] == "REVOKED"
    for device in registered_devices
)

metric1, metric2, metric3, metric4 = st.columns(4)

metric1.metric(
    "Registered Devices",
    len(registered_devices),
)

metric2.metric(
    "Pending",
    pending_count,
)

metric3.metric(
    "Active",
    active_count,
)

metric4.metric(
    "Revoked",
    revoked_count,
)


tabs = st.tabs(
    [
        "Registration",
        "Batch & Epoch",
        "Proof Verification",
        "Revocation",
        "Device Registry",
        "Audit Logs",
    ]
)


# -------------------------------------------------------------------
# Registration tab
# -------------------------------------------------------------------


with tabs[0]:
    st.header("Device Registration")

    st.info(
        "The dashboard automatically performs PSK authentication, "
        "DID/public-key submission and ECC proof-of-possession."
    )

    selected_profile_name = st.selectbox(
        "Select a simulated device",
        options=list(DEVICE_PROFILES.keys()),
        key="registration_device",
    )

    selected_profile = DEVICE_PROFILES[
        selected_profile_name
    ]

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Device ID",
        selected_profile["device_id"],
    )

    col2.metric(
        "Device Type",
        selected_profile["device_type"],
    )

    col3.metric(
        "Role",
        selected_profile["role"],
    )

    if st.button(
        "Register Selected Device",
        type="primary",
        use_container_width=True,
    ):
        register_device(
            selected_profile
        )

    st.divider()

    st.subheader("Automatic Batch Registration")

    st.write(
        "Register every available simulated IIoT device "
        "using the complete authentication protocol."
    )

    if st.button(
        "Register All Demo Devices",
        use_container_width=True,
    ):
        progress = st.progress(0)
        successful = 0

        for index, profile in enumerate(
            DEVICE_PROFILES.values()
        ):
            if register_device(profile):
                successful += 1

            progress.progress(
                (index + 1)
                / len(DEVICE_PROFILES)
            )

        st.success(
            f"{successful} devices registered successfully"
        )


# -------------------------------------------------------------------
# Batch and epoch tab
# -------------------------------------------------------------------


with tabs[1]:
    st.header("Registration Batch and Epoch")

    current_devices = get_devices()

    pending_devices = [
        device
        for device in current_devices
        if device["status"] == "PENDING"
    ]

    active_devices = [
        device
        for device in current_devices
        if device["status"] == "ACTIVE"
    ]

    col1, col2 = st.columns(2)

    col1.metric(
        "Pending Devices",
        len(pending_devices),
    )

    col2.metric(
        "Active Devices",
        len(active_devices),
    )

    if pending_devices:
        st.subheader("Open Registration Batch")

        pending_table = [
            {
                "Device ID": device["device_id"],
                "DID": device["did"],
                "Type": device["device_type"],
                "Role": device["role"],
                "Status": device["status"],
            }
            for device in pending_devices
        ]

        st.dataframe(
            pd.DataFrame(pending_table),
            use_container_width=True,
            hide_index=True,
        )

        if st.button(
            "Finalize Registration Batch",
            type="primary",
            use_container_width=True,
        ):
            result = api_request(
                "POST",
                "/batch/finalize",
            )

            if result is not None:
                add_log(
                    f"Epoch {result['epoch_id']} finalized "
                    f"with {result['device_count']} devices",
                    "PASS",
                )

                add_log(
                    f"Trusted Merkle root anchored: "
                    f"{result['merkle_root']}",
                    "PASS",
                )

                st.success(
                    f"Epoch {result['epoch_id']} "
                    f"finalized successfully"
                )

                st.write(
                    f"**Devices included:** "
                    f"{result['device_count']}"
                )

                st.write("**Trusted Merkle root**")

                st.code(
                    result["merkle_root"],
                    language=None,
                )

                st.rerun()

    else:
        st.info(
            "There are no pending devices in the open batch."
        )

    st.divider()

    st.subheader("Trusted Root Registry")

    epochs = get_epochs()

    if epochs:
        epoch_table = [
            {
                "Epoch": epoch["epoch_id"],
                "Merkle Root": epoch["merkle_root"],
                "Device Count": epoch["device_count"],
                "Created At": epoch["created_at"],
            }
            for epoch in epochs
        ]

        st.dataframe(
            pd.DataFrame(epoch_table),
            use_container_width=True,
            hide_index=True,
        )

    else:
        st.info(
            "No epoch root has been anchored yet."
        )


# -------------------------------------------------------------------
# Proof verification tab
# -------------------------------------------------------------------


with tabs[2]:
    st.header("Merkle Inclusion-Proof Verification")

    devices = get_devices()
    epochs = get_epochs()

    proof_devices = [
        device
        for device in devices
        if device["status"] in {
            "ACTIVE",
            "REVOKED",
        }
    ]

    if not proof_devices:
        st.info(
            "Finalize a batch before verifying "
            "device inclusion proofs."
        )

    elif not epochs:
        st.info(
            "No trusted epoch is available."
        )

    else:
        device_labels = {
            get_device_label(device): device
            for device in proof_devices
        }

        selected_label = st.selectbox(
            "Select device",
            options=list(
                device_labels.keys()
            ),
            key="proof_device",
        )

        selected_device = device_labels[
            selected_label
        ]

        selected_epoch_id = st.selectbox(
            "Select epoch",
            options=[
                epoch["epoch_id"]
                for epoch in epochs
            ],
            key="proof_epoch",
        )

        if st.button(
            "Load Inclusion Proof",
            use_container_width=True,
        ):
            proof = api_request(
                "GET",
                (
                    f"/epochs/{selected_epoch_id}"
                    f"/devices/{selected_device['did']}"
                    f"/proof"
                ),
            )

            if proof is not None:
                st.session_state.latest_proof = proof
                st.session_state.latest_proof_device = (
                    selected_device
                )

                add_log(
                    f"Inclusion proof loaded for "
                    f"{selected_device['device_id']}",
                    "INFO",
                )

        if (
            st.session_state.latest_proof
            is not None
            and st.session_state.latest_proof_device
            is not None
        ):
            proof = st.session_state.latest_proof
            proof_device = (
                st.session_state.latest_proof_device
            )

            st.subheader("Proof Package")

            col1, col2 = st.columns(2)

            col1.metric(
                "Epoch",
                proof["epoch_id"],
            )

            col2.metric(
                "Proof Path Length",
                len(proof["siblings"]),
            )

            st.write("**Device leaf**")

            st.code(
                proof["leaf"],
                language=None,
            )

            proof_table = [
                {
                    "Level": index + 1,
                    "Sibling Hash": sibling[
                        "hash"
                    ],
                    "Position": sibling[
                        "position"
                    ],
                }
                for index, sibling in enumerate(
                    proof["siblings"]
                )
            ]

            st.dataframe(
                pd.DataFrame(proof_table),
                use_container_width=True,
                hide_index=True,
            )

            if st.button(
                "Verify Inclusion Proof",
                type="primary",
                use_container_width=True,
            ):
                result = api_request(
                    "POST",
                    "/identity/verify",
                    json={
                        "did": proof_device[
                            "did"
                        ],
                        "public_key": proof_device[
                            "public_key"
                        ],
                        "epoch_id": proof[
                            "epoch_id"
                        ],
                        "proof": proof,
                    },
                )

                if result is not None:
                    if result["success"]:
                        st.success(
                            "IDENTITY VERIFIED: "
                            "The reconstructed root matches "
                            "the trusted epoch root."
                        )

                        add_log(
                            f"{proof_device['device_id']}: "
                            f"Merkle proof verified",
                            "ALLOW",
                        )

                    elif (
                        result["code"]
                        == "DEVICE_REVOKED"
                    ):
                        st.warning(
                            "Historical proof is valid, "
                            "but current access is denied "
                            "because the device is revoked."
                        )

                        add_log(
                            f"{proof_device['device_id']}: "
                            f"historical proof valid but "
                            f"device revoked",
                            "DENY",
                        )

                    else:
                        st.error(
                            f"{result['code']}: "
                            f"{result['message']}"
                        )

                        add_log(
                            f"{proof_device['device_id']}: "
                            f"proof verification failed — "
                            f"{result['code']}",
                            "DENY",
                        )

                    st.json(result)


# -------------------------------------------------------------------
# Revocation tab
# -------------------------------------------------------------------


with tabs[3]:
    st.header("Device Revocation")

    st.warning(
        "Revocation takes effect immediately. An old proof may "
        "remain historically valid, but it cannot authorize "
        "current resource access."
    )

    devices = get_devices()

    revocable_devices = [
        device
        for device in devices
        if device["status"] != "REVOKED"
    ]

    revoked_devices = [
        device
        for device in devices
        if device["status"] == "REVOKED"
    ]

    if revocable_devices:
        revocation_labels = {
            get_device_label(device): device
            for device in revocable_devices
        }

        selected_revocation_label = st.selectbox(
            "Select a device to revoke",
            options=list(
                revocation_labels.keys()
            ),
            key="revocation_device",
        )

        selected_revocation_device = (
            revocation_labels[
                selected_revocation_label
            ]
        )

        revocation_reason = st.text_input(
            "Revocation reason",
            value="Administrative security revocation",
        )

        confirmation = st.checkbox(
            "I understand that this immediately "
            "blocks the device"
        )

        if st.button(
            "Revoke Device",
            type="primary",
            disabled=not confirmation,
            use_container_width=True,
        ):
            result = api_request(
                "POST",
                (
                    f"/devices/"
                    f"{selected_revocation_device['did']}"
                    f"/revoke"
                ),
                json={
                    "reason": revocation_reason,
                },
            )

            if result is not None:
                add_log(
                    f"{selected_revocation_device['device_id']}: "
                    f"device revoked — {revocation_reason}",
                    "DENY",
                )

                st.success(
                    f"{selected_revocation_device['device_id']} "
                    f"was revoked immediately."
                )

                st.rerun()

    else:
        st.info(
            "No active or pending devices are available "
            "for revocation."
        )

    st.divider()

    st.subheader("Revoked Devices")

    if revoked_devices:
        revoked_table = [
            {
                "Device ID": device["device_id"],
                "DID": device["did"],
                "Type": device["device_type"],
                "Role": device["role"],
                "Status": device["status"],
            }
            for device in revoked_devices
        ]

        st.dataframe(
            pd.DataFrame(revoked_table),
            use_container_width=True,
            hide_index=True,
        )

        st.info(
            "Open the Proof Verification tab and verify a "
            "revoked device to demonstrate the difference "
            "between historical membership and current status."
        )

    else:
        st.info("No devices have been revoked.")


# -------------------------------------------------------------------
# Device registry tab
# -------------------------------------------------------------------


with tabs[4]:
    st.header("Device Registry")

    devices = get_devices()

    if devices:
        registry_table = [
            {
                "Device ID": device["device_id"],
                "DID": device["did"],
                "Type": device["device_type"],
                "Role": device["role"],
                "Zone": device["zone"],
                "Status": device["status"],
                "PSK Authentication": (
                    "PASS"
                    if device[
                        "authentication_complete"
                    ]
                    else "FAIL"
                ),
                "Proof of Possession": (
                    "PASS"
                    if device["pop_verified"]
                    else "FAIL"
                ),
            }
            for device in devices
        ]

        st.dataframe(
            pd.DataFrame(registry_table),
            use_container_width=True,
            hide_index=True,
        )

    else:
        st.info(
            "No devices have been registered."
        )


# -------------------------------------------------------------------
# Logs tab
# -------------------------------------------------------------------


with tabs[5]:
    st.header("Audit and Security Logs")

    if st.button("Clear Dashboard Logs"):
        st.session_state.logs = []
        st.rerun()

    if st.session_state.logs:
        log_table = pd.DataFrame(
            reversed(
                st.session_state.logs
            )
        )

        st.dataframe(
            log_table,
            use_container_width=True,
            hide_index=True,
        )

    else:
        st.info(
            "No events have been recorded "
            "during this dashboard session."
        )