# Shared Contracts — Do Not Change Independently

## Selected design

- Python 3.11, FastAPI, SQLite/SQLAlchemy
- ECDSA P-256 with SHA-256
- Standard Merkle tree; leaves sorted as raw bytes
- Odd Merkle node is duplicated
- JWT temporary tokens signed by the fog
- Append-only epoch/root records in SQLite

## Phase 1 → Phase 2 boundary

Phase 1 must produce `AuthenticatedDevice` from `fog/schemas.py`. Phase 2 accepts exactly that model, so it can initially use a mock instance.

## Canonical Merkle leaf

```text
SHA256(UTF8(DID) || UTF8(PEM_PUBLIC_KEY))
```

Hash values are bytes internally and lowercase hexadecimal in JSON or logs.

## Canonical signed resource request

```text
DID|RESOURCE|OPERATION|BODY_HASH|NONCE|TIMESTAMP|TOKEN_JTI
```

For permanent access with no token, the final field is an empty string. UTF-8 encode the exact string before ECDSA signing.

## Common decisions/error codes

- `PSK_AUTH_FAILED`
- `POP_FAILED`
- `CHALLENGE_REUSED`
- `DEVICE_REVOKED`
- `TOKEN_INVALID`
- `TOKEN_EXPIRED`
- `TOKEN_REVOKED`
- `TOKEN_BINDING_FAILED`
- `NONCE_REUSED`
- `STALE_TIMESTAMP`
- `REQUEST_SIGNATURE_INVALID`
- `EPOCH_NOT_FOUND`
- `INCLUSION_PROOF_INVALID`
- `POLICY_DENIED`
- `ACCESS_ALLOWED`

## Phase 2 (Member 2) — implemented

- `fog/token_service.py`: issues fog-signed JWT provisional tokens (claims: `jti`,
  `sub`=DID, `pk_thumbprint`, `device_type`, `role`, `status`, `permitted_actions`,
  `iat`, `exp`); validates signature, expiry, token revocation and device revocation.
- `fog/access_service.py::process_temporary_access`: full pipeline — token
  validity -> device/token binding (DID + public-key fingerprint match) ->
  timestamp freshness -> fresh-nonce enforcement (`used_nonces`, unique on
  `(did, nonce)`) -> request proof-of-possession (ECDSA signature over the
  canonical string) -> provisional policy check.
- `fog/revocation.py::revoke_token_placeholder`: persists immediate token
  revocation to `revoked_tokens`.
- `fog/models.py::BatchQueue`: devices are queued (`included=False`) as soon as
  they receive a temporary token. Member 1's Phase-1 batch finalization should
  mark rows `included=True` once each device's leaf is folded into a finalized
  epoch root. `GET /batch/queue` lists devices still waiting.

## Integration rule

Neither member changes `schemas.py`, this contract, the leaf rule, or the request signing format without agreeing first and committing the change to `main`.

