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
- `DEVICE_NOT_FOUND` (added in Phase 3: permanent access resolved a valid inclusion
  proof for a DID with no local device record to read a device type/role from)

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

## Phase 3 (Member 2) — implemented

- `fog/access_service.py::process_permanent_access`: recomputes the leaf
  `H(DID || PK)` and rejects immediately if it doesn't match the submitted
  proof's leaf; looks up the trusted root for `epoch_id` (`EPOCH_NOT_FOUND` if
  missing); verifies the Merkle inclusion proof against that root
  (`INCLUSION_PROOF_INVALID` -- this is what catches a tampered DID, public
  key, leaf, or sibling hash); checks device revocation (`DEVICE_REVOKED`);
  timestamp freshness (`STALE_TIMESTAMP`) and fresh-nonce enforcement
  (`NONCE_REUSED`, same `used_nonces` table Phase 2 uses); request-signature
  verification against the submitted public key with an empty final field in
  the canonical string (`REQUEST_SIGNATURE_INVALID`); then role-based /
  resource-operation authorization from `config/policies.json`'s `permanent`
  rules, keyed by device type (`POLICY_DENIED`, or `DEVICE_NOT_FOUND` if no
  local device record exists to resolve a device type from). Returns the same
  structured `DecisionResponse` (`success`, `code`, `message`, `decision`,
  `details`) as Phase 2, with a clear rejection reason on every DENY.
- `fog/merkle.py::generate_inclusion_proof` / `verify_inclusion_proof`: filled
  in (were `NotImplementedError`) using the same sort-and-duplicate-odd-node
  rule as `build_merkle_root`, since Phase 3 verification needs them. Still
  conceptually Member 1's file/ownership.
- `fog/revocation.py::revoke_device_placeholder`: now persists to
  `revoked_devices` and flips the local `Device.status`, so both Phase 2 and
  Phase 3 immediately reject a revoked device even with an otherwise-valid
  token or a structurally valid old inclusion proof.
- `POST /batch/finalize-demo`: a stand-in for Member 1's real windowed batch
  build. Takes `{devices: [{did, public_key}, ...]}`, sorts their leaves,
  computes one epoch root, anchors it in `epochs`, stores each device's
  inclusion proof in `device_proofs`, and marks their `batch_queue` rows
  `included=True`. Exists so `/access/permanent` is testable end-to-end;
  replace with the real registration-window/batch logic from Phase 1.

## Integration rule

Neither member changes `schemas.py`, this contract, the leaf rule, or the request signing format without agreeing first and committing the change to `main`.

