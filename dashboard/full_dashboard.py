"""Streamlit dashboard for the complete IIoT identity framework.

Run the API:
    python -m uvicorn fog.app:app --reload

Run this dashboard in a second terminal:
    python -m streamlit run dashboard/full_dashboard.py
"""

from __future__ import annotations

import copy
import hashlib
import secrets
import time
from pathlib import Path
from typing import Any

import httpx
import jwt
import pandas as pd
import streamlit as st

from devices.device import SimulatedDevice


DEFAULT_API_URL = "http://127.0.0.1:8000"

DEVICE_PROFILES = {
    "Temperature Sensor 1": {
        "device_id": "TEMP-001", "device_type": "temperature_sensor",
        "role": "sensor", "psk": "temp-device-secret-001",
    },
    "Temperature Sensor 2": {
        "device_id": "TEMP-002", "device_type": "temperature_sensor",
        "role": "sensor", "psk": "temp-device-secret-002",
    },
    "Pressure Sensor": {
        "device_id": "PRESS-001", "device_type": "pressure_sensor",
        "role": "sensor", "psk": "pressure-device-secret-001",
    },
    "Camera": {
        "device_id": "CAM-001", "device_type": "camera",
        "role": "monitor", "psk": "camera-device-secret-001",
    },
    "Valve Controller": {
        "device_id": "VALVE-001", "device_type": "valve_controller",
        "role": "actuator", "psk": "valve-device-secret-001",
    },
    "Motor Controller": {
        "device_id": "MOTOR-001", "device_type": "motor_controller",
        "role": "actuator", "psk": "motor-device-secret-001",
    },
    "Smart Meter": {
        "device_id": "METER-001", "device_type": "smart_meter",
        "role": "sensor", "psk": "meter-device-secret-001",
    },
}

st.set_page_config(page_title="IIoT Identity Framework", page_icon="🔐", layout="wide")

STATE_DEFAULTS = {
    "simulated_devices": {},
    "logs": [],
    "latest_proof": None,
    "latest_proof_device": None,
    "latest_token": None,
    "latest_jti": None,
    "latest_token_did": None,
    "latest_token_device_id": None,
}
for state_key, default in STATE_DEFAULTS.items():
    if state_key not in st.session_state:
        st.session_state[state_key] = default


def add_log(message: str, category: str = "INFO") -> None:
    st.session_state.logs.append({
        "time": time.strftime("%H:%M:%S"), "category": category, "message": message
    })


def api_request(method: str, path: str, *, quiet: bool = False, **kwargs: Any) -> Any | None:
    try:
        response = httpx.request(method, f"{st.session_state.api_url}{path}", timeout=30, **kwargs)
    except httpx.RequestError as exc:
        if not quiet:
            st.error(f"Fog API is unavailable: {exc}\n\nStart it with `python -m uvicorn fog.app:app --reload`.")
        return None
    try:
        body = response.json()
    except ValueError:
        body = response.text
    if response.status_code >= 400:
        if not quiet:
            st.error(f"API request failed ({response.status_code}): {body}")
        return {"_error": True, "status_code": response.status_code, "body": body}
    return body


def successful(result: Any) -> bool:
    return result is not None and not (isinstance(result, dict) and result.get("_error"))


def get_devices() -> list[dict]:
    result = api_request("GET", "/devices", quiet=True)
    return result if isinstance(result, list) else []


def get_epochs() -> list[dict]:
    result = api_request("GET", "/epochs", quiet=True)
    return result if isinstance(result, list) else []


def label(device: dict) -> str:
    return f"{device.get('device_id', 'unknown')} — {device.get('status', 'unknown')}"


DEFAULT_ACCESS = {
    "temperature_sensor": ("temperature_readings", "WRITE"),
    "pressure_sensor": ("pressure_readings", "WRITE"),
    "smart_meter": ("energy_readings", "WRITE"),
    "camera": ("video_stream", "READ"),
    "valve_controller": ("valve", "OPEN"),
    "motor_controller": ("motor", "START"),
}


def local_device(device_record: dict) -> SimulatedDevice | None:
    """Return the simulator that owns this device's private key."""
    return st.session_state.simulated_devices.get(device_record.get("device_id"))


def token_jti(token: str) -> str:
    """Read the JTI for request binding; the API still verifies the JWT."""
    return str(jwt.decode(token, options={"verify_signature": False})["jti"])


def signed_access_fields(
    simulator: SimulatedDevice,
    resource: str,
    operation: str,
    jti: str = "",
) -> dict:
    """Build a fresh resource request signed by the device's P-256 key."""
    return simulator.build_signed_request(
        resource=resource,
        operation=operation,
        body_hash=hashlib.sha256(b"").hexdigest(),
        nonce=secrets.token_urlsafe(18),
        timestamp=int(time.time()),
        token_jti=jti,
    )


def register_device(profile: dict) -> bool:
    device = SimulatedDevice(**profile)
    add_log(f"{device.device_id}: requested PSK authentication challenge")
    auth = api_request("POST", "/auth/challenge", json={"device_id": device.device_id})
    if not successful(auth):
        add_log(f"{device.device_id}: challenge failed", "DENY")
        return False

    nonce = auth["nonce"]
    begin = api_request("POST", "/registration/begin", json={
        "device_id": device.device_id,
        "auth_nonce": nonce,
        "auth_hmac": device.create_psk_response(nonce),
        "did": device.did,
        "public_key": device.public_key_pem,
        "device_type": device.device_type,
        "role": device.role,
        "zone": device.zone,
    })
    if not successful(begin):
        add_log(f"{device.device_id}: PSK authentication failed", "DENY")
        return False

    complete = api_request("POST", "/registration/complete", json={
        "registration_id": begin["registration_id"],
        "signature": device.sign_challenge(begin["challenge"]),
    })
    if not successful(complete):
        add_log(f"{device.device_id}: ECC proof-of-possession failed", "DENY")
        return False

    st.session_state.simulated_devices[device.device_id] = device
    add_log(f"{device.device_id}: registered; PSK and ECC PoP passed", "PASS")
    st.success(f"{device.device_id} registered and added to the pending batch.")
    st.json(complete)
    return True


def load_proof(device: dict, epoch_id: int) -> Any | None:
    proof = api_request("GET", f"/epochs/{epoch_id}/devices/{device['did']}/proof")
    if successful(proof):
        st.session_state.latest_proof = proof
        st.session_state.latest_proof_device = device
        add_log(f"Loaded epoch {epoch_id} proof for {device['device_id']}")
        return proof
    return None


def permanent_payload(device: dict, proof: dict, resource: str, operation: str) -> dict | None:
    simulator = local_device(device)
    if simulator is None:
        return None
    return {
        "did": device["did"], "public_key": device["public_key"],
        "epoch_id": proof["epoch_id"], "proof": proof,
        **signed_access_fields(simulator, resource, operation),
    }


with st.sidebar:
    st.header("Connection")
    st.session_state.api_url = st.text_input("Fog API URL", DEFAULT_API_URL).rstrip("/")
    st.caption("Start FastAPI first, then use this dashboard.")
    if st.button("Refresh dashboard", use_container_width=True):
        st.rerun()

st.title("🔐 IIoT Decentralized Identity & Access Control")
st.caption("PSK onboarding · ECC proof-of-possession · JWT temporary access · Merkle permanent identity · revocation")

health = api_request("GET", "/health", quiet=True)
if not successful(health):
    st.error("Fog API is offline. Run `python -m uvicorn fog.app:app --reload` in another terminal.")
    st.stop()
st.success(f"Fog node online — {health.get('zone', 'configured zone')}")

devices = get_devices()
epochs = get_epochs()
pending = sum(d.get("status") == "PENDING" for d in devices)
active = sum(d.get("status") == "ACTIVE" for d in devices)
revoked = sum(d.get("status") == "REVOKED" for d in devices)
for column, title, value in zip(st.columns(5),
                                ["Registered", "Pending", "Active", "Revoked", "Epochs"],
                                [len(devices), pending, active, revoked, len(epochs)]):
    column.metric(title, value)

tabs = st.tabs([
    "1 · Registration", "2 · Batch & Merkle", "3 · Temporary Access",
    "4 · Permanent Access", "5 · Revocation", "6 · Security Attacks",
    "Registry", "Benchmarks", "Audit Log",
])

with tabs[0]:
    st.header("Phase 1 — Secure device registration")
    st.info("The UI automatically performs nonce-based PSK authentication and ECC proof-of-possession.")
    selected_name = st.selectbox("Demo device", list(DEVICE_PROFILES), key="registration_profile")
    profile = DEVICE_PROFILES[selected_name]
    c1, c2, c3 = st.columns(3)
    c1.metric("Device ID", profile["device_id"])
    c2.metric("Type", profile["device_type"])
    c3.metric("Role", profile["role"])
    if st.button("Register selected device", type="primary", use_container_width=True):
        register_device(profile)
    if st.button("Register all demo devices", use_container_width=True):
        bar = st.progress(0)
        count = 0
        for index, item in enumerate(DEVICE_PROFILES.values(), 1):
            count += int(register_device(item))
            bar.progress(index / len(DEVICE_PROFILES))
        st.success(f"{count} device(s) registered.")

with tabs[1]:
    st.header("Phase 1 — Merkle batch and trusted epochs")
    pending_devices = [d for d in get_devices() if d.get("status") == "PENDING"]
    if pending_devices:
        st.dataframe(pd.DataFrame(pending_devices), use_container_width=True, hide_index=True)
        if st.button("Finalize pending batch", type="primary", use_container_width=True):
            result = api_request("POST", "/batch/finalize")
            if successful(result):
                add_log(f"Finalized epoch {result.get('epoch_id')}; anchored Merkle root", "PASS")
                st.success("Batch finalized. Devices are now active.")
                st.json(result)
    else:
        st.info("No pending devices. Register a device first, or the batch has already been finalized.")
    st.subheader("Trusted root registry")
    current_epochs = get_epochs()
    if current_epochs:
        st.dataframe(pd.DataFrame(current_epochs), use_container_width=True, hide_index=True)
    else:
        st.info("No trusted epoch exists yet.")

with tabs[2]:
    st.header("Phase 2 — Temporary JWT access")
    st.write("Issue a short-lived signed token after onboarding, then use it for resource access.")
    active_devices = [d for d in get_devices() if d.get("status") in {"PENDING", "ACTIVE"}]
    if not active_devices:
        st.info("Register a non-revoked device first.")
    else:
        mapping = {label(d): d for d in active_devices}
        selected = mapping[st.selectbox("Active device", list(mapping), key="temporary_device")]
        default_resource, default_operation = DEFAULT_ACCESS.get(
            selected["device_type"], ("temperature_readings", "WRITE")
        )
        col1, col2 = st.columns(2)
        resource = col1.text_input("Resource", default_resource, key="temp_resource")
        operation = col2.text_input("Operation", default_operation, key="temp_operation").upper()
        simulator = local_device(selected)
        if simulator is None:
            st.warning("Private key unavailable in this dashboard session. Reset the demo database and register this device through the dashboard.")
        if st.button("Issue temporary token", type="primary", use_container_width=True):
            result = api_request("POST", "/token/issue", json={"device": {
                "device_id": selected["device_id"], "did": selected["did"],
                "public_key": selected["public_key"],
                "public_key_thumbprint": hashlib.sha256(selected["public_key"].encode()).hexdigest(),
                "device_type": selected["device_type"], "role": selected["role"],
                "zone": selected["zone"],
                "authentication_complete": selected["authentication_complete"],
                "proof_of_possession_verified": selected["pop_verified"],
                "status": selected["status"],
            }})
            if successful(result):
                st.session_state.latest_token = result["access_token"]
                st.session_state.latest_jti = token_jti(result["access_token"])
                st.session_state.latest_token_did = selected["did"]
                st.session_state.latest_token_device_id = selected["device_id"]
                add_log(f"Issued temporary JWT for {selected['device_id']}", "PASS")
                st.success("Temporary token issued.")
                st.json(result)
        if st.session_state.latest_token:
            st.code(st.session_state.latest_token, language=None)
            if st.button("Request temporary access", disabled=simulator is None, use_container_width=True):
                result = api_request("POST", "/access/temporary", json={
                    "token": st.session_state.latest_token,
                    **signed_access_fields(
                        simulator, resource, operation, token_jti(st.session_state.latest_token)
                    ),
                })
                if successful(result):
                    allowed = result.get("success", result.get("allowed", True))
                    (st.success if allowed else st.error)("ACCESS ALLOWED" if allowed else "ACCESS DENIED")
                    add_log(f"Temporary access {'allowed' if allowed else 'denied'} for {resource}",
                            "ALLOW" if allowed else "DENY")
                    st.json(result)

with tabs[3]:
    st.header("Phase 3 — Permanent Merkle identity access")
    proof_devices = [d for d in get_devices() if d.get("status") in {"ACTIVE", "REVOKED"}]
    current_epochs = get_epochs()
    if not proof_devices or not current_epochs:
        st.info("Register devices and finalize a batch first.")
    else:
        mapping = {label(d): d for d in proof_devices}
        selected = mapping[st.selectbox("Device", list(mapping), key="permanent_device")]
        epoch_id = st.selectbox("Trusted epoch", [e["epoch_id"] for e in current_epochs], key="permanent_epoch")
        default_resource, default_operation = DEFAULT_ACCESS.get(
            selected["device_type"], ("temperature_readings", "READ")
        )
        if selected["device_type"] in {"temperature_sensor", "pressure_sensor", "smart_meter"}:
            default_operation = "READ"
        c1, c2 = st.columns(2)
        resource = c1.text_input("Resource", default_resource, key="permanent_resource")
        operation = c2.text_input("Operation", default_operation, key="permanent_operation").upper()
        if st.button("Load inclusion proof", use_container_width=True):
            load_proof(selected, epoch_id)
        proof = st.session_state.latest_proof
        proof_device = st.session_state.latest_proof_device
        if proof and proof_device:
            st.subheader("Merkle proof package")
            st.json(proof)
            if st.button("Verify identity only", use_container_width=True):
                result = api_request("POST", "/identity/verify", json={
                    "did": proof_device["did"], "public_key": proof_device["public_key"],
                    "epoch_id": proof["epoch_id"], "proof": proof,
                })
                if successful(result):
                    st.json(result)
                    add_log("Permanent identity proof verification executed", "PASS" if result.get("success") else "DENY")
            if st.button("Request permanent access", type="primary", use_container_width=True):
                payload = permanent_payload(proof_device, proof, resource, operation)
                if payload is None:
                    st.error("Private key unavailable. Reset the database and register the device through this dashboard.")
                    result = None
                else:
                    result = api_request("POST", "/access/permanent", json=payload)
                if successful(result):
                    allowed = result.get("success", result.get("allowed", True))
                    (st.success if allowed else st.error)("PERMANENT ACCESS ALLOWED" if allowed else "ACCESS DENIED")
                    add_log(f"Permanent access {'allowed' if allowed else 'denied'}", "ALLOW" if allowed else "DENY")
                    st.json(result)

with tabs[4]:
    st.header("Immediate revocation")
    left, right = st.columns(2)
    with left:
        st.subheader("Revoke device")
        revocable = [d for d in get_devices() if d.get("status") != "REVOKED"]
        if revocable:
            mapping = {label(d): d for d in revocable}
            selected = mapping[st.selectbox("Device", list(mapping), key="revoke_device")]
            reason = st.text_input("Reason", "Administrative security revocation", key="device_reason")
            confirm = st.checkbox("Confirm device revocation")
            if st.button("Revoke device", disabled=not confirm, use_container_width=True):
                result = api_request("POST", f"/devices/{selected['did']}/revoke", json={"reason": reason})
                if successful(result):
                    add_log(f"Revoked {selected['device_id']}: {reason}", "DENY")
                    st.success("Device revoked immediately.")
                    st.json(result)
        else:
            st.info("No revocable devices.")
    with right:
        st.subheader("Revoke temporary token")
        jti = st.text_input("Token JTI", st.session_state.latest_jti or "")
        reason = st.text_input("Reason", "Suspected token compromise", key="token_reason")
        if st.button("Revoke token", disabled=not bool(jti), use_container_width=True):
            result = api_request("POST", f"/tokens/{jti}/revoke", json={"reason": reason})
            if successful(result):
                add_log(f"Revoked temporary token {jti}", "DENY")
                st.success("Token revoked immediately.")
                st.json(result)

with tabs[5]:
    st.header("Security attack demonstrations")
    st.caption("Each demonstration should be denied by the backend; denial is the expected PASS result.")
    a1, a2 = st.columns(2)
    with a1:
        st.subheader("Attack 1: Tampered JWT")
        st.write("Changes a signed token after issuance. Signature verification must reject it.")
        if st.button("Run tampered-token attack", disabled=not bool(st.session_state.latest_token), use_container_width=True):
            token = st.session_state.latest_token
            tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
            simulator = st.session_state.simulated_devices.get(st.session_state.latest_token_device_id)
            signed = signed_access_fields(
                simulator, "temperature_readings", "WRITE", token_jti(token)
            ) if simulator else {}
            result = api_request("POST", "/access/temporary", quiet=True,
                                 json={"token": tampered, **signed})
            denied = not successful(result) or not result.get("success", result.get("allowed", False))
            (st.success if denied else st.error)("PASS — tampered JWT denied" if denied else "FAIL — attack was accepted")
            add_log("Tampered-JWT attack denied" if denied else "Tampered-JWT attack accepted", "PASS" if denied else "FAIL")
            st.json(result)
    with a2:
        st.subheader("Attack 2: Revoked-token replay")
        st.write("Reuses the latest token after its JTI has been placed in the revocation registry.")
        if st.button("Run revoked-token replay", disabled=not bool(st.session_state.latest_token), use_container_width=True):
            simulator = st.session_state.simulated_devices.get(st.session_state.latest_token_device_id)
            signed = signed_access_fields(
                simulator, "temperature_readings", "WRITE", token_jti(st.session_state.latest_token)
            ) if simulator else {}
            result = api_request("POST", "/access/temporary", quiet=True,
                                 json={"token": st.session_state.latest_token, **signed})
            denied = not successful(result) or not result.get("success", result.get("allowed", False))
            (st.success if denied else st.warning)("PASS — replay denied" if denied else "Token is not revoked yet; revoke it first.")
            add_log("Revoked-token replay demonstration executed", "PASS" if denied else "INFO")
            st.json(result)
    a3, a4 = st.columns(2)
    with a3:
        st.subheader("Attack 3: Tampered Merkle proof")
        st.write("Changes a sibling hash. The reconstructed root must no longer match the trusted root.")
        if st.button("Run proof-tampering attack", disabled=not bool(st.session_state.latest_proof), use_container_width=True):
            proof = copy.deepcopy(st.session_state.latest_proof)
            device = st.session_state.latest_proof_device
            if proof.get("siblings"):
                proof["siblings"][0]["hash"] = "0" * 64
            else:
                proof["leaf"] = "0" * 64
            result = api_request("POST", "/identity/verify", quiet=True, json={
                "did": device["did"], "public_key": device["public_key"],
                "epoch_id": proof["epoch_id"], "proof": proof,
            })
            denied = not successful(result) or not result.get("success", False)
            (st.success if denied else st.error)("PASS — forged proof denied" if denied else "FAIL — forged proof accepted")
            add_log("Tampered-Merkle-proof attack denied" if denied else "Forged proof accepted", "PASS" if denied else "FAIL")
            st.json(result)
    with a4:
        st.subheader("Attack 4: Epoch mismatch")
        st.write("Claims a proof belongs to a different trusted epoch.")
        if st.button("Run epoch-mismatch attack", disabled=not bool(st.session_state.latest_proof), use_container_width=True):
            proof = copy.deepcopy(st.session_state.latest_proof)
            device = st.session_state.latest_proof_device
            claimed_epoch = int(proof["epoch_id"]) + 999
            payload = permanent_payload(device, proof, "temperature_readings", "READ")
            result = api_request("POST", "/access/permanent", quiet=True, json={
                **(payload or {}), "epoch_id": claimed_epoch,
            })
            denied = not successful(result) or not result.get("success", result.get("allowed", False))
            (st.success if denied else st.error)("PASS — epoch mismatch denied" if denied else "FAIL — mismatch accepted")
            add_log("Epoch-mismatch attack denied" if denied else "Epoch mismatch accepted", "PASS" if denied else "FAIL")
            st.json(result)

with tabs[6]:
    st.header("System registry")
    st.subheader("Devices")
    current_devices = get_devices()
    if current_devices:
        st.dataframe(pd.DataFrame(current_devices), use_container_width=True, hide_index=True)
    else:
        st.info("No registered devices.")
    st.subheader("Epochs")
    current_epochs = get_epochs()
    if current_epochs:
        st.dataframe(pd.DataFrame(current_epochs), use_container_width=True, hide_index=True)
    else:
        st.info("No finalized epochs.")

with tabs[7]:
    st.header("Performance evaluation")
    results_dir = Path("performance/results")
    summary_path = results_dir / "full_system_summary.csv"
    if summary_path.exists():
        st.dataframe(pd.read_csv(summary_path), use_container_width=True, hide_index=True)
        chart_files = [
            "registration_latency.png", "merkle_batch_time.png",
            "verification_latency.png", "verification_throughput.png",
        ]
        for left, right in zip(chart_files[::2], chart_files[1::2]):
            c1, c2 = st.columns(2)
            c1.image(str(results_dir / left), use_container_width=True)
            c2.image(str(results_dir / right), use_container_width=True)
    else:
        st.info("Run `python -m performance.benchmark_full_system` to generate results.")

with tabs[8]:
    st.header("Dashboard audit log")
    if st.button("Clear audit log"):
        st.session_state.logs = []
        st.rerun()
    if st.session_state.logs:
        st.dataframe(pd.DataFrame(reversed(st.session_state.logs)), use_container_width=True, hide_index=True)
    else:
        st.info("No dashboard events recorded in this session.")
