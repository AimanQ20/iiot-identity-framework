"""MEMBER 2 leads request validation; Member 1 supplies permanent proof verification."""

from fog.schemas import DecisionResponse, PermanentAccessRequest, TemporaryAccessRequest


def process_temporary_access(request: TemporaryAccessRequest) -> DecisionResponse:
    """TODO MEMBER 2: token, expiry, nonce, revocation, PoP and policy checks."""
    return DecisionResponse(
        success=False,
        code="NOT_IMPLEMENTED",
        message="Temporary access pipeline belongs to Member 2",
        decision="DENY",
    )


def process_permanent_access(request: PermanentAccessRequest) -> DecisionResponse:
    """Joint integration: Member 1 verifies proof; Member 2 authorizes request."""
    return DecisionResponse(
        success=False,
        code="NOT_IMPLEMENTED",
        message="Permanent verification and authorization are not integrated yet",
        decision="DENY",
    )

