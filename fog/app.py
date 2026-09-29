"""Combined FastAPI application for the IIoT identity framework."""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from fog.access_service import (
    process_permanent_access,
    process_temporary_access,
)
from fog.database import Base, engine, get_db
from fog.models import BatchQueue, Device, Epoch
from fog.registration import (
    begin_registration,
    complete_registration,
    finalize_epoch,
    get_device_proof,
    issue_authentication_challenge,
)
from fog.revocation import (
    revoke_device,
    revoke_token,
)
from fog.schemas import (
    AuthenticationChallengeRequest,
    AuthenticationChallengeResponse,
    BeginRegistrationRequest,
    CompleteRegistrationRequest,
    PermanentAccessRequest,
    ProofOfPossessionChallengeResponse,
    RegistrationResponse,
    RevokeRequest,
    TemporaryAccessRequest,
    TokenIssueRequest,
    TokenResponse,
    VerifyIdentityRequest,
)
from fog.token_service import issue_temporary_token
from fog.verification import verify_permanent_identity


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Create database tables when the fog application starts."""

    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Single-Zone IIoT Identity Framework",
    description=(
        "Device registration, temporary access, Merkle identity "
        "verification, authorization and revocation"
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# -------------------------------------------------------------------
# System health
# -------------------------------------------------------------------


@app.get("/health")
def health():
    return {
        "status": "ok",
        "zone": "zone-1",
    }


# -------------------------------------------------------------------
# Phase 1: Device authentication and registration
# -------------------------------------------------------------------


@app.post(
    "/auth/challenge",
    response_model=AuthenticationChallengeResponse,
)
def authentication_challenge(
    request: AuthenticationChallengeRequest,
):
    """Issue a fresh nonce for initial PSK authentication."""

    try:
        nonce, expires_in = issue_authentication_challenge(
            request.device_id
        )

        return AuthenticationChallengeResponse(
            device_id=request.device_id,
            nonce=nonce,
            expires_in=expires_in,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc


@app.post(
    "/registration/begin",
    response_model=ProofOfPossessionChallengeResponse,
)
def registration_begin(
    request: BeginRegistrationRequest,
    db: Session = Depends(get_db),
):
    """Verify PSK authentication and issue a PoP challenge."""

    try:
        registration_id, challenge, expires_in = (
            begin_registration(
                request,
                db,
            )
        )

        return ProofOfPossessionChallengeResponse(
            registration_id=registration_id,
            challenge=challenge,
            expires_in=expires_in,
        )

    except PermissionError as exc:
        raise HTTPException(
            status_code=401,
            detail=str(exc),
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


@app.post(
    "/registration/complete",
    response_model=RegistrationResponse,
)
def registration_complete(
    request: CompleteRegistrationRequest,
    db: Session = Depends(get_db),
):
    """Verify proof-of-possession and add the device to the batch."""

    result = complete_registration(
        request,
        db,
    )

    if not result.success:
        raise HTTPException(
            status_code=401,
            detail=result.model_dump(),
        )

    return result


# -------------------------------------------------------------------
# Phase 1: Batch finalization and trusted epoch roots
# -------------------------------------------------------------------


@app.post("/batch/finalize")
def batch_finalize(
    db: Session = Depends(get_db),
):
    """Finalize pending devices into one stable epoch root."""

    try:
        result = finalize_epoch(db)

        # A device waiting through Phase 2 is no longer queued after
        # its inclusion proof is generated in the finalized epoch.
        included_dids = result.get(
            "proofs",
            {},
        ).keys()

        for did in included_dids:
            (
                db.query(BatchQueue)
                .filter(
                    BatchQueue.did == did,
                    BatchQueue.included.is_(False),
                )
                .update(
                    {"included": True},
                    synchronize_session=False,
                )
            )

        db.commit()

        return result

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


@app.get("/batch/queue")
def batch_queue(
    db: Session = Depends(get_db),
):
    """List devices waiting for permanent batch inclusion."""

    rows = (
        db.query(BatchQueue)
        .filter(BatchQueue.included.is_(False))
        .order_by(BatchQueue.queued_at.asc())
        .all()
    )

    return [
        {
            "did": row.did,
            "device_type": row.device_type,
            "role": row.role,
            "queued_at": row.queued_at.isoformat(),
            "included": row.included,
        }
        for row in rows
    ]


@app.get(
    "/epochs/{epoch_id}/devices/{did}/proof"
)
def retrieve_proof(
    epoch_id: int,
    did: str,
    db: Session = Depends(get_db),
):
    """Retrieve a device-specific inclusion proof."""

    try:
        return get_device_proof(
            did,
            epoch_id,
            db,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc


# -------------------------------------------------------------------
# Phase 2: Temporary token bridging
# -------------------------------------------------------------------


@app.post(
    "/token/issue",
    response_model=TokenResponse,
)
def issue_token(
    request: TokenIssueRequest,
    db: Session = Depends(get_db),
):
    """Issue a short-lived provisional access token."""

    try:
        token, ttl = issue_temporary_token(
            request.device,
            db,
        )

        return TokenResponse(
            access_token=token,
            expires_in=ttl,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=401,
            detail=str(exc),
        ) from exc


@app.post("/access/temporary")
def temporary_access(
    request: TemporaryAccessRequest,
    db: Session = Depends(get_db),
):
    """Validate a provisional token and temporary resource request."""

    return process_temporary_access(
        request,
        db,
    )


# -------------------------------------------------------------------
# Phase 3: Permanent proof-based access
# -------------------------------------------------------------------


@app.post("/identity/verify")
def verify_identity(
    request: VerifyIdentityRequest,
    db: Session = Depends(get_db),
):
    """Verify identity and historical membership without resource access."""

    return verify_permanent_identity(
        did=request.did,
        public_key=request.public_key,
        epoch_id=request.epoch_id,
        proof=request.proof,
        db=db,
    )


@app.post("/access/permanent")
def permanent_access(
    request: PermanentAccessRequest,
    db: Session = Depends(get_db),
):
    """Verify membership, request freshness and authorization policy."""

    if request.proof.epoch_id != request.epoch_id:
        return {
            "success": False,
            "code": "EPOCH_MISMATCH",
            "message": (
                "Proof epoch does not match the requested epoch"
            ),
            "decision": "DENY",
            "details": {},
        }

    return process_permanent_access(
        request,
        db,
    )


# -------------------------------------------------------------------
# Revocation
# -------------------------------------------------------------------


@app.post("/devices/{did}/revoke")
def revoke_registered_device(
    did: str,
    request: RevokeRequest,
    db: Session = Depends(get_db),
):
    """Immediately revoke a registered device."""

    try:
        return revoke_device(
            did,
            request.reason,
            db,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc


@app.post("/tokens/{jti}/revoke")
def revoke_temporary_token(
    jti: str,
    request: RevokeRequest,
    db: Session = Depends(get_db),
):
    """Immediately revoke a temporary token."""

    return revoke_token(
        jti=jti,
        reason=request.reason,
        db=db,
    )


# -------------------------------------------------------------------
# Dashboard support
# -------------------------------------------------------------------


@app.get("/devices")
def list_devices(
    db: Session = Depends(get_db),
):
    """List registered devices."""

    devices = (
        db.query(Device)
        .order_by(Device.registered_at.asc())
        .all()
    )

    return [
        {
            "device_id": device.device_id,
            "did": device.did,
            "device_type": device.device_type,
            "role": device.role,
            "zone": device.zone,
            "status": device.status,
            "authentication_complete": (
                device.authentication_complete
            ),
            "pop_verified": device.pop_verified,
            "public_key": device.public_key,
        }
        for device in devices
    ]


@app.get("/epochs")
def list_epochs(
    db: Session = Depends(get_db),
):
    """List trusted epoch roots."""

    epochs = (
        db.query(Epoch)
        .order_by(Epoch.epoch_id.desc())
        .all()
    )

    return [
        {
            "epoch_id": epoch.epoch_id,
            "merkle_root": epoch.merkle_root,
            "device_count": epoch.device_count,
            "created_at": epoch.created_at,
        }
        for epoch in epochs
    ]