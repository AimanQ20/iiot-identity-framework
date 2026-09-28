from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from fog.access_service import process_permanent_access, process_temporary_access
from fog.database import Base, engine, get_db
from fog.merkle import build_merkle_root, generate_inclusion_proof
from fog.models import BatchQueue, DeviceProof, Epoch
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


class BatchFinalizeDevice(BaseModel):
    did: str
    public_key: str


class BatchFinalizeRequest(BaseModel):
    devices: list[BatchFinalizeDevice]


@app.post("/batch/finalize-demo")
def finalize_batch_demo(request: BatchFinalizeRequest, db: Session = Depends(get_db)):
    """Stand-in for Member 1's real windowed batch-finalization step: sorts the
    given devices' leaves, computes one epoch root, anchors it, and stores a
    per-device inclusion proof -- exactly what /access/permanent needs to
    verify against. Replace with the real batch/registration-window logic."""
    if not request.devices:
        raise HTTPException(status_code=400, detail="At least one device is required to finalize a batch")

    leaves = [create_device_leaf(d.did, d.public_key) for d in request.devices]
    root = build_merkle_root(leaves)

    next_epoch_id = (db.query(Epoch.epoch_id).order_by(Epoch.epoch_id.desc()).first() or (0,))[0] + 1
    db.add(Epoch(epoch_id=next_epoch_id, merkle_root=root.hex(), device_count=len(leaves)))

    proofs = {}
    for device, leaf in zip(request.devices, leaves):
        proof_steps = generate_inclusion_proof(leaves, leaf)
        proofs[device.did] = {"epoch_id": next_epoch_id, "leaf": leaf.hex(), "siblings": proof_steps}
        db.add(
            DeviceProof(
                did=device.did,
                epoch_id=next_epoch_id,
                leaf=leaf.hex(),
                proof_json=str(proof_steps),
            )
        )
        db.query(BatchQueue).filter_by(did=device.did, included=False).update({"included": True})

    db.commit()
    return {"epoch_id": next_epoch_id, "root": root.hex(), "proofs": proofs}


@app.get("/batch/queue")
def batch_queue(db: Session = Depends(get_db)):
    """Devices currently queued (Phase 2) waiting for the next finalized batch."""
    rows = db.query(BatchQueue).filter_by(included=False).order_by(BatchQueue.queued_at).all()
    return [
        {
            "did": row.did,
            "device_type": row.device_type,
            "role": row.role,
            "queued_at": row.queued_at.isoformat(),
        }
        for row in rows
    ]


@app.post("/token/issue", response_model=TokenResponse)
def issue_token(request: TokenIssueRequest, db: Session = Depends(get_db)):
    try:
        token, ttl = issue_temporary_token(request.device, db)
        return TokenResponse(access_token=token, expires_in=ttl)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@app.post("/access/temporary")
def temporary_access(request: TemporaryAccessRequest, db: Session = Depends(get_db)):
    return process_temporary_access(request, db)


@app.post("/access/permanent")
def permanent_access(request: PermanentAccessRequest, db: Session = Depends(get_db)):
    return process_permanent_access(request, db)


@app.post("/devices/{did}/revoke")
def revoke_device(did: str, request: RevokeRequest, db: Session = Depends(get_db)):
    return revoke_device_placeholder(did, request.reason, db)


@app.post("/tokens/{jti}/revoke")
def revoke_token(jti: str, request: RevokeRequest, db: Session = Depends(get_db)):
    return revoke_token_placeholder(jti, request.reason, db)
