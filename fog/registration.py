"""MEMBER 1: Phase 1 registration, authentication and batch formation."""

import hashlib

from fog.schemas import AuthenticatedDevice


def public_key_thumbprint(public_key_pem: str) -> str:
    return hashlib.sha256(public_key_pem.encode("utf-8")).hexdigest()


def create_device_leaf(did: str, public_key_pem: str) -> bytes:
    """Shared canonical leaf rule. Do not change without updating CONTRACTS.md."""
    return hashlib.sha256(did.encode("utf-8") + public_key_pem.encode("utf-8")).digest()


def authenticate_and_register_placeholder(device: AuthenticatedDevice) -> AuthenticatedDevice:
    """Replace with PSK challenge-response and ECC proof-of-possession."""
    if not device.authentication_complete or not device.proof_of_possession_verified:
        raise ValueError("PSK authentication and proof-of-possession are required")
    return device


def finalize_epoch_placeholder() -> dict:
    """Replace with sorting, Merkle construction, root anchoring and proof generation."""
    return {"status": "NOT_IMPLEMENTED", "owner": "member-1"}

