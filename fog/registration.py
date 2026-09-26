"""Phase 1 registration, authentication and batch formation.

MEMBER 1:
- PSK challenge-response
- ECC proof-of-possession
- DID/public-key validation
- Pending-device registration
- Merkle leaf creation
"""
import json

from fog.merkle import (
    build_merkle_root,
    generate_inclusion_proof,
)
from fog.models import DeviceProof, Epoch, RevokedDevice
import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy.orm import Session

from fog.models import Device
from fog.schemas import (
    AuthenticatedDevice,
    BeginRegistrationRequest,
    CompleteRegistrationRequest,
    DeviceStatus,
    RegistrationResponse,
)


AUTH_CHALLENGE_TTL_SECONDS = 120
POP_CHALLENGE_TTL_SECONDS = 120


# Demo PSKs.
# In a production system, these would be stored securely or provisioned
# using a secret-management system.
DEVICE_PSKS = {
    "TEMP-001": "temp-device-secret-001",
    "TEMP-002": "temp-device-secret-002",
    "PRESS-001": "pressure-device-secret-001",
    "CAM-001": "camera-device-secret-001",
    "VALVE-001": "valve-device-secret-001",
    "MOTOR-001": "motor-device-secret-001",
    "METER-001": "meter-device-secret-001",
    "ATTACKER-001": "attacker-device-secret-001",
}


@dataclass
class StoredAuthenticationChallenge:
    nonce: str
    expires_at: float
    used: bool = False


@dataclass
class PendingRegistration:
    registration_id: str
    request: BeginRegistrationRequest
    pop_challenge: str
    expires_at: float


# These stores are suitable for a single-process assignment demonstration.
# Restarting the fog clears unfinished challenges.
_authentication_challenges: dict[str, StoredAuthenticationChallenge] = {}
_pending_registrations: dict[str, PendingRegistration] = {}


def public_key_thumbprint(public_key_pem: str) -> str:
    """Calculate the public-key fingerprint."""

    return hashlib.sha256(
        public_key_pem.encode("utf-8")
    ).hexdigest()


def create_device_leaf(did: str, public_key_pem: str) -> bytes:
    """Create Ld = SHA256(DID || public_key)."""

    return hashlib.sha256(
        did.encode("utf-8") + public_key_pem.encode("utf-8")
    ).digest()


def derive_did(public_key_pem: str) -> str:
    """Derive the expected DID from the supplied public key."""

    digest = public_key_thumbprint(public_key_pem)
    return f"did:iiot:{digest[:32]}"


def issue_authentication_challenge(device_id: str) -> tuple[str, int]:
    """Generate a fresh nonce for PSK authentication."""

    if device_id not in DEVICE_PSKS:
        raise ValueError("Unknown or unprovisioned device")

    nonce = secrets.token_urlsafe(32)

    _authentication_challenges[device_id] = StoredAuthenticationChallenge(
        nonce=nonce,
        expires_at=time.time() + AUTH_CHALLENGE_TTL_SECONDS,
    )

    return nonce, AUTH_CHALLENGE_TTL_SECONDS


def verify_psk_response(
    device_id: str,
    received_nonce: str,
    received_hmac: str,
) -> bool:
    """Verify the device's one-time HMAC response."""

    stored_challenge = _authentication_challenges.get(device_id)

    if stored_challenge is None:
        return False

    if stored_challenge.used:
        return False

    if time.time() > stored_challenge.expires_at:
        _authentication_challenges.pop(device_id, None)
        return False

    if not hmac.compare_digest(stored_challenge.nonce, received_nonce):
        return False

    psk = DEVICE_PSKS.get(device_id)

    if psk is None:
        return False

    message = f"{device_id}|{received_nonce}".encode("utf-8")

    expected_hmac = hmac.new(
        psk.encode("utf-8"),
        message,
        hashlib.sha256,
    ).hexdigest()

    valid = hmac.compare_digest(expected_hmac, received_hmac)

    # A successful authentication nonce cannot be used again.
    if valid:
        stored_challenge.used = True

    return valid


def validate_public_key(public_key_pem: str):
    """Load and validate an ECC P-256 public key."""

    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid public-key encoding") from exc

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("The submitted public key is not an ECC public key")

    if not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("The public key must use the P-256 curve")

    return public_key


def begin_registration(
    request: BeginRegistrationRequest,
    db: Session,
) -> tuple[str, str, int]:
    """Verify PSK authentication and issue a PoP challenge."""

    if not verify_psk_response(
        request.device_id,
        request.auth_nonce,
        request.auth_hmac,
    ):
        raise PermissionError("PSK authentication failed")

    # Confirm that a valid P-256 public key was submitted.
    validate_public_key(request.public_key)

    # Stop a device from claiming a DID that does not match its key.
    expected_did = derive_did(request.public_key)

    if not hmac.compare_digest(expected_did, request.did):
        raise ValueError("DID does not match the submitted public key")

    existing_device = db.query(Device).filter(
        (Device.device_id == request.device_id)
        | (Device.did == request.did)
    ).first()

    if existing_device is not None:
        raise ValueError("Device ID or DID is already registered")

    registration_id = str(uuid4())
    pop_challenge = secrets.token_urlsafe(32)

    _pending_registrations[registration_id] = PendingRegistration(
        registration_id=registration_id,
        request=request,
        pop_challenge=pop_challenge,
        expires_at=time.time() + POP_CHALLENGE_TTL_SECONDS,
    )

    return (
        registration_id,
        pop_challenge,
        POP_CHALLENGE_TTL_SECONDS,
    )


def verify_pop_signature(
    public_key_pem: str,
    challenge: str,
    signature_base64: str,
) -> bool:
    """Verify proof-of-possession using the device public key."""

    try:
        public_key = validate_public_key(public_key_pem)
        signature = base64.b64decode(
            signature_base64.encode("ascii"),
            validate=True,
        )

        public_key.verify(
            signature,
            challenge.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )

        return True

    except (
        InvalidSignature,
        ValueError,
        TypeError,
        base64.binascii.Error,
    ):
        return False


def complete_registration(
    request: CompleteRegistrationRequest,
    db: Session,
) -> RegistrationResponse:
    """Verify PoP and store the authenticated device as PENDING."""

    pending = _pending_registrations.get(request.registration_id)

    if pending is None:
        return RegistrationResponse(
            success=False,
            code="REGISTRATION_NOT_FOUND",
            message="Registration session does not exist",
        )

    if time.time() > pending.expires_at:
        _pending_registrations.pop(request.registration_id, None)

        return RegistrationResponse(
            success=False,
            code="POP_CHALLENGE_EXPIRED",
            message="Proof-of-possession challenge has expired",
        )

    if not verify_pop_signature(
        pending.request.public_key,
        pending.pop_challenge,
        request.signature,
    ):
        return RegistrationResponse(
            success=False,
            code="POP_FAILED",
            message="Proof-of-possession signature is invalid",
        )

    thumbprint = public_key_thumbprint(pending.request.public_key)

    device = Device(
        device_id=pending.request.device_id,
        did=pending.request.did,
        public_key=pending.request.public_key,
        public_key_thumbprint=thumbprint,
        device_type=pending.request.device_type.value,
        role=pending.request.role,
        zone=pending.request.zone,
        status=DeviceStatus.PENDING.value,
        authentication_complete=True,
        pop_verified=True,
    )

    db.add(device)
    db.commit()
    db.refresh(device)

    leaf = create_device_leaf(
        device.did,
        device.public_key,
    ).hex()

    authenticated_device = AuthenticatedDevice(
        device_id=device.device_id,
        did=device.did,
        public_key=device.public_key,
        public_key_thumbprint=device.public_key_thumbprint,
        device_type=device.device_type,
        role=device.role,
        zone=device.zone,
        authentication_complete=device.authentication_complete,
        proof_of_possession_verified=device.pop_verified,
        status=device.status,
    )

    # A PoP challenge must be one-time use.
    _pending_registrations.pop(request.registration_id, None)

    return RegistrationResponse(
        success=True,
        code="REGISTRATION_PENDING_BATCH",
        message=(
            "Device authenticated successfully and added "
            "to the open registration batch"
        ),
        device=authenticated_device,
        leaf=leaf,
    )
def finalize_epoch(db: Session) -> dict:
    """Finalize all eligible PENDING devices into one stable epoch."""

    pending_devices = (
        db.query(Device)
        .filter(Device.status == DeviceStatus.PENDING.value)
        .order_by(Device.did.asc())
        .all()
    )

    if not pending_devices:
        raise ValueError("There are no pending devices to finalize")

    revoked_dids = {
        row.did
        for row in db.query(RevokedDevice).all()
    }

    eligible_devices = [
        device
        for device in pending_devices
        if device.did not in revoked_dids
    ]

    if not eligible_devices:
        raise ValueError(
            "All pending devices have been revoked"
        )

    device_leaves = {
        device.did: create_device_leaf(
            device.did,
            device.public_key,
        )
        for device in eligible_devices
    }

    leaves = list(device_leaves.values())
    merkle_root = build_merkle_root(leaves)

    latest_epoch = (
        db.query(Epoch)
        .order_by(Epoch.epoch_id.desc())
        .first()
    )

    next_epoch_id = (
        1 if latest_epoch is None
        else latest_epoch.epoch_id + 1
    )

    epoch = Epoch(
        epoch_id=next_epoch_id,
        merkle_root=merkle_root.hex(),
        device_count=len(eligible_devices),
    )

    db.add(epoch)

    proof_packages = {}

    for device in eligible_devices:
        leaf = device_leaves[device.did]

        proof = generate_inclusion_proof(
            leaves,
            leaf,
        )

        proof_package = {
            "epoch_id": next_epoch_id,
            "leaf": leaf.hex(),
            "siblings": proof,
        }

        stored_proof = DeviceProof(
            did=device.did,
            epoch_id=next_epoch_id,
            leaf=leaf.hex(),
            proof_json=json.dumps(proof_package),
        )

        db.add(stored_proof)

        device.status = DeviceStatus.ACTIVE.value

        proof_packages[device.did] = proof_package

    db.commit()

    return {
        "success": True,
        "code": "EPOCH_FINALIZED",
        "epoch_id": next_epoch_id,
        "device_count": len(eligible_devices),
        "merkle_root": merkle_root.hex(),
        "proofs": proof_packages,
    }


def get_device_proof(
    did: str,
    epoch_id: int,
    db: Session,
) -> dict:
    """Retrieve a stored inclusion proof."""

    stored_proof = (
        db.query(DeviceProof)
        .filter(
            DeviceProof.did == did,
            DeviceProof.epoch_id == epoch_id,
        )
        .first()
    )

    if stored_proof is None:
        raise ValueError(
            "No inclusion proof exists for this device and epoch"
        )

    return json.loads(stored_proof.proof_json)