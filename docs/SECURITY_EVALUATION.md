# Security Evaluation

The final implementation evaluates attacks against the same FastAPI, SQLite,
JWT, ECC and Merkle services used by the application. A blocked request is the
expected successful outcome of an attack test.

## Required attack demonstrations

| Attack | Attacker capability | Detection and defense | Expected result |
|---|---|---|---|
| Exact request replay | Captures and resends a previously valid signed request | Persistent `(DID, nonce)` uniqueness and timestamp freshness checks | `NONCE_REUSED` / DENY |
| Identity or proof tampering | Modifies DID, public key, leaf or a sibling hash | Recompute `H(DID || public key)` and reconstruct the root against the trusted epoch root | `INCLUSION_PROOF_INVALID` / DENY |
| Stolen temporary token | Copies a valid JWT but does not possess the device private key | JWT subject/key binding and ECDSA signature over the resource request | `REQUEST_SIGNATURE_INVALID` / DENY |
| Expired or revoked credential | Reuses a token after TTL or administrative revocation | JWT expiry verification and persistent token/device revocation lookup | `TOKEN_EXPIRED`, `TOKEN_REVOKED` or `DEVICE_REVOKED` / DENY |

## Additional checks

- Wrong PSK and replayed authentication nonces are rejected during onboarding.
- A DID that does not match its submitted public key is rejected.
- Proof-of-possession must be signed by the corresponding P-256 private key.
- A valid identity cannot perform an operation denied by the JSON policy.
- Stale timestamps are rejected outside the 60-second freshness window.
- A proof submitted under a different or unknown epoch is rejected.
- A historical Merkle proof remains evidence of past inclusion, but a revoked
  device cannot use that proof for current access.

## Running the evaluation

```powershell
python -m pytest tests/test_security_attacks.py -q
python -m pytest -q
```

The dashboard also contains interactive demonstrations under the **Security
Attacks** tab. The automated tests are the authoritative repeatable evidence.

## Security limitations

This is a single-zone educational prototype. The unfinished registration
challenge stores are process-local, the default development JWT secret must be
replaced outside demonstrations, and the API must be placed behind TLS and
administrator authentication before any real deployment.
