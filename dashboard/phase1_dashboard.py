"""Streamlit Phase 1 demonstration dashboard."""

import time

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


if "devices" not in st.session_state:
    st.session_state.devices = {}

if "logs" not in st.session_state:
    st.session_state.logs = []


def log(message: str):
    timestamp = time.strftime("%H:%M:%S")
    st.session_state.logs.append(
        f"[{timestamp}] {message}"
    )


def api_request(method: str, path: str, **kwargs):
    try:
        response = httpx.request(
            method,
            f"{API_URL}{path}",
            timeout=30,
            **kwargs,
        )

        if response.status_code >= 400:
            st.error(
                f"API error {response.status_code}: "
                f"{response.text}"
            )
            return None

        return response.json()

    except httpx.RequestError:
        st.error(
            "Fog server is not running. Start it with:\n\n"
            "`python -m uvicorn fog.app:app --reload`"
        )
        return None


def register_device(profile: dict):
    device = SimulatedDevice(**profile)

    auth_data = api_request(
        "POST",
        "/auth/challenge",
        json={
            "device_id": device.device_id,
        },
    )

    if auth_data is None:
        return

    log(
        f"{device.device_id}: authentication nonce issued"
    )

    auth_hmac = device.create_psk_response(
        auth_data["nonce"]
    )

    begin_data = api_request(
        "POST",
        "/registration/begin",
        json={
            "device_id": device.device_id,
            "auth_nonce": auth_data["nonce"],
            "auth_hmac": auth_hmac,
            "did": device.did,
            "public_key": device.public_key_pem,
            "device_type": device.device_type,
            "role": device.role,
            "zone": device.zone,
        },
    )

    if begin_data is None:
        return

    log(
        f"{device.device_id}: PSK authentication passed"
    )

    signature = device.sign_challenge(
        begin_data["challenge"]
    )

    complete_data = api_request(
        "POST",
        "/registration/complete",
        json={
            "registration_id": (
                begin_data["registration_id"]
            ),
            "signature": signature,
        },
    )

    if complete_data is None:
        return

    st.session_state.devices[
        device.device_id
    ] = device

    log(
        f"{device.device_id}: proof-of-possession passed"
    )
    log(
        f"{device.device_id}: added to pending batch"
    )

    st.success(
        f"{device.device_id} registered successfully"
    )

    with st.expander(
        f"Registration result: {device.device_id}",
        expanded=True,
    ):
        st.write("**DID**")
        st.code(complete_data["device"]["did"])

        st.write("**Merkle leaf**")
        st.code(complete_data["leaf"])

        st.write(
            f"**Status:** "
            f"{complete_data['device']['status']}"
        )


st.title("Single-Zone IIoT Identity Framework")
st.caption(
    "Device registration, proof-of-possession, "
    "Merkle batching and identity verification"
)

health = api_request("GET", "/health")

if health:
    st.success(
        f"Fog node online — {health['zone']}"
    )
else:
    st.stop()


tab1, tab2, tab3, tab4 = st.tabs(
    [
        "Device Registration",
        "Batch & Epoch",
        "Registered Devices",
        "System Logs",
    ]
)


with tab1:
    st.subheader("Register an IIoT Device")

    selected_name = st.selectbox(
        "Select a simulated device",
        list(DEVICE_PROFILES.keys()),
    )

    selected_profile = DEVICE_PROFILES[
        selected_name
    ]

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Device ID",
        selected_profile["device_id"],
    )
    col2.metric(
        "Type",
        selected_profile["device_type"],
    )
    col3.metric(
        "Role",
        selected_profile["role"],
    )

    if st.button(
        "Register Selected Device",
        type="primary",
    ):
        register_device(selected_profile)

    st.divider()

    if st.button("Register All Demo Devices"):
        progress = st.progress(0)

        for index, profile in enumerate(
            DEVICE_PROFILES.values()
        ):
            register_device(profile)

            progress.progress(
                (index + 1) / len(DEVICE_PROFILES)
            )

        st.success(
            "All available demo devices processed"
        )


with tab2:
    st.subheader("Registration Batch")

    devices = api_request("GET", "/devices")

    if devices is not None:
        pending_devices = [
            device
            for device in devices
            if device["status"] == "PENDING"
        ]

        active_devices = [
            device
            for device in devices
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

    if st.button(
        "Finalize Registration Batch",
        type="primary",
    ):
        epoch = api_request(
            "POST",
            "/batch/finalize",
        )

        if epoch:
            log(
                f"Epoch {epoch['epoch_id']} finalized"
            )

            st.success(
                f"Epoch {epoch['epoch_id']} finalized"
            )

            st.write("**Trusted Merkle root**")
            st.code(epoch["merkle_root"])

            st.write(
                f"**Devices included:** "
                f"{epoch['device_count']}"
            )

    st.divider()
    st.subheader("Trusted Epoch Registry")

    epochs = api_request("GET", "/epochs")

    if epochs:
        st.dataframe(
            pd.DataFrame(epochs),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No finalized epochs yet")


with tab3:
    st.subheader("Registered Devices")

    devices = api_request("GET", "/devices")

    if devices:
        display_rows = [
            {
                "Device ID": device["device_id"],
                "DID": device["did"],
                "Type": device["device_type"],
                "Role": device["role"],
                "Status": device["status"],
                "PSK Auth": (
                    "Passed"
                    if device[
                        "authentication_complete"
                    ]
                    else "Failed"
                ),
                "PoP": (
                    "Passed"
                    if device["pop_verified"]
                    else "Failed"
                ),
            }
            for device in devices
        ]

        st.dataframe(
            pd.DataFrame(display_rows),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No devices registered")


with tab4:
    st.subheader("Security and Registration Logs")

    if st.session_state.logs:
        for entry in reversed(
            st.session_state.logs
        ):
            st.code(entry)
    else:
        st.info("No events recorded in this session")