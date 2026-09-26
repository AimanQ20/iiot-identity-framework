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

## Integration rule

Neither member changes `schemas.py`, this contract, the leaf rule, or the request signing format without agreeing first and committing the change to `main`.

