from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from fog.access_service import process_permanent_access, process_temporary_access
from fog.database import Base, engine
from fog.merkle import build_merkle_root
from fog.registration import authenticate_and_register_placeholder, create_device_leaf
from fog.revocation import revoke_device_placeholder, revoke_token_placeholder
from fog.schemas import (
    AuthenticatedDevice,
    PermanentAccessRequest,
    RevokeRequest,
    TemporaryAccessRequest,
    TokenIssueRequest,
    TokenResponse,
)
from fog.token_service import issue_temporary_token


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Single-Zone IIoT Identity Framework",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health():
    return {"status": "ok", "zone": "zone-1"}


@app.post("/registration/mock")
def mock_registration(device: AuthenticatedDevice):
    """Temporary integration endpoint; Member 1 replaces it with real registration."""
    try:
        accepted = authenticate_and_register_placeholder(device)
        leaf = create_device_leaf(accepted.did, accepted.public_key)
        return {"device": accepted, "leaf": leaf.hex(), "status": "PENDING"}
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@app.post("/batch/demo-root")
def demo_root(hex_leaves: list[str]):
    """Small working endpoint proving the shared Merkle helper runs."""
    try:
        root = build_merkle_root([bytes.fromhex(item) for item in hex_leaves])
        return {"root": root.hex(), "leaf_count": len(hex_leaves)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/token/issue", response_model=TokenResponse)
def issue_token(request: TokenIssueRequest):
    try:
        token, ttl = issue_temporary_token(request.device)
        return TokenResponse(access_token=token, expires_in=ttl)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@app.post("/access/temporary")
def temporary_access(request: TemporaryAccessRequest):
    return process_temporary_access(request)


@app.post("/access/permanent")
def permanent_access(request: PermanentAccessRequest):
    return process_permanent_access(request)


@app.post("/devices/{did}/revoke")
def revoke_device(did: str, request: RevokeRequest):
    return revoke_device_placeholder(did, request.reason)


@app.post("/tokens/{jti}/revoke")
def revoke_token(jti: str, request: RevokeRequest):
    return revoke_token_placeholder(jti, request.reason)

