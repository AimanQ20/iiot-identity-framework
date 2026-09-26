from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from fog.database import Base, engine, get_db
from fog.registration import (
    begin_registration,
    complete_registration,
    finalize_epoch,
    get_device_proof,
    issue_authentication_challenge,
)
from fog.revocation import revoke_device
from fog.schemas import (
    AuthenticationChallengeRequest,
    AuthenticationChallengeResponse,
    BeginRegistrationRequest,
    CompleteRegistrationRequest,
    ProofOfPossessionChallengeResponse,
    RegistrationResponse,
    RevokeRequest,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Single-Zone IIoT Identity Framework",
    version="0.2.0",
    lifespan=lifespan,
)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "zone": "zone-1",
    }


@app.post(
    "/auth/challenge",
    response_model=AuthenticationChallengeResponse,
)
def authentication_challenge(
    request: AuthenticationChallengeRequest,
):
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
    try:
        registration_id, challenge, expires_in = begin_registration(
            request,
            db,
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
    result = complete_registration(request, db)

    if not result.success:
        raise HTTPException(
            status_code=401,
            detail=result.model_dump(),
        )

    return result


@app.post("/batch/finalize")
def batch_finalize(
    db: Session = Depends(get_db),
):
    try:
        return finalize_epoch(db)

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


@app.get("/epochs/{epoch_id}/devices/{did}/proof")
def retrieve_proof(
    epoch_id: int,
    did: str,
    db: Session = Depends(get_db),
):
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


@app.post("/devices/{did}/revoke")
def revoke_registered_device(
    did: str,
    request: RevokeRequest,
    db: Session = Depends(get_db),
):
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