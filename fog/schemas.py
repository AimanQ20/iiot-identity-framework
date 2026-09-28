from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DeviceStatus(str, Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


class DeviceType(str, Enum):
    TEMPERATURE_SENSOR = "temperature_sensor"
    PRESSURE_SENSOR = "pressure_sensor"
    CAMERA = "camera"
    VALVE_CONTROLLER = "valve_controller"
    MOTOR_CONTROLLER = "motor_controller"
    SMART_METER = "smart_meter"


class AuthenticatedDevice(BaseModel):
    """Shared output of Phase 1 and input to Phase 2."""

    device_id: str
    did: str
    public_key: str
    public_key_thumbprint: str
    device_type: DeviceType
    role: str
    zone: str = "zone-1"
    authentication_complete: bool
    proof_of_possession_verified: bool
    status: DeviceStatus = DeviceStatus.PENDING


class TokenIssueRequest(BaseModel):
    device: AuthenticatedDevice


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class MerkleSibling(BaseModel):
    hash: str
    position: str = Field(pattern="^(left|right)$")


class InclusionProof(BaseModel):
    epoch_id: int
    leaf: str
    siblings: list[MerkleSibling]


class TemporaryAccessRequest(BaseModel):
    token: str
    did: str
    resource: str
    operation: str
    body_hash: str
    nonce: str
    timestamp: int
    signature: str


class PermanentAccessRequest(BaseModel):
    did: str
    public_key: str
    epoch_id: int
    proof: InclusionProof
    resource: str
    operation: str
    body_hash: str
    nonce: str
    timestamp: int
    signature: str


class DecisionResponse(BaseModel):
    success: bool
    code: str
    message: str
    decision: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class RevokeRequest(BaseModel):
    reason: str = "Administrative revocation"

