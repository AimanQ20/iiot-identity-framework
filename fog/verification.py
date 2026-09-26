"""Permanent epoch-bound identity verification.

Member 1 verifies cryptographic identity and Merkle membership.
Member 2 applies resource authorization after successful verification.
"""

from sqlalchemy.orm import Session

from fog.merkle import verify_inclusion_proof
from fog.models import Device, Epoch, RevokedDevice
from fog.registration import create_device_leaf
from fog.schemas import DecisionResponse, InclusionProof


def verify_permanent_identity(
    did: str,
    public_key: str,
    epoch_id: int,
    proof: InclusionProof,
    db: Session,
) -> DecisionResponse:
    """Verify a device against its trusted epoch root."""

    # Obtain the trusted root for the requested epoch.
    epoch = (
        db.query(Epoch)
        .filter(Epoch.epoch_id == epoch_id)
        .first()
    )

    if epoch is None:
        return DecisionResponse(
            success=False,
            code="EPOCH_NOT_FOUND",
            message="The supplied epoch does not exist",
            decision="DENY",
        )

    # Find the currently registered device.
    device = (
        db.query(Device)
        .filter(Device.did == did)
        .first()
    )

    if device is None:
        return DecisionResponse(
            success=False,
            code="DEVICE_NOT_FOUND",
            message="The DID is not registered",
            decision="DENY",
        )

    # Prevent substitution of another public key.
    if device.public_key != public_key:
        return DecisionResponse(
            success=False,
            code="PUBLIC_KEY_MISMATCH",
            message=(
                "Submitted public key does not match "
                "the registered device"
            ),
            decision="DENY",
        )

    # Recompute Ld = H(DID || public key).
    expected_leaf = create_device_leaf(
        did,
        public_key,
    )

    if proof.leaf.lower() != expected_leaf.hex():
        return DecisionResponse(
            success=False,
            code="LEAF_MISMATCH",
            message=(
                "Submitted leaf does not match "
                "the DID and public key"
            ),
            decision="DENY",
        )

    raw_proof = [
        {
            "hash": sibling.hash,
            "position": sibling.position,
        }
        for sibling in proof.siblings
    ]

    # Reconstruct the root and compare it with the trusted root.
    proof_valid = verify_inclusion_proof(
        leaf=expected_leaf,
        proof=raw_proof,
        trusted_root=bytes.fromhex(
            epoch.merkle_root
        ),
    )

    if not proof_valid:
        return DecisionResponse(
            success=False,
            code="INCLUSION_PROOF_INVALID",
            message=(
                "Reconstructed root does not match "
                "the trusted epoch root"
            ),
            decision="DENY",
        )

    # A historical proof may be valid even after revocation.
    revocation = (
        db.query(RevokedDevice)
        .filter(RevokedDevice.did == did)
        .first()
    )

    if (
        revocation is not None
        or device.status == "REVOKED"
    ):
        return DecisionResponse(
            success=False,
            code="DEVICE_REVOKED",
            message=(
                "Historical inclusion proof is valid, "
                "but the device is currently revoked"
            ),
            decision="DENY",
            details={
                "historical_proof_valid": True,
                "current_authorization": False,
                "did": did,
                "epoch_id": epoch_id,
            },
        )

    return DecisionResponse(
        success=True,
        code="IDENTITY_VERIFIED",
        message="Device membership proof is valid",
        details={
            "did": did,
            "device_type": device.device_type,
            "role": device.role,
            "epoch_id": epoch_id,
            "identity_verified": True,
        },
    )