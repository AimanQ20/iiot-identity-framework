# Security Attack Demonstrations

The authoritative automated demonstrations are in
`tests/test_security_attacks.py` and cover:

1. Exact signed-request replay
2. Tampered Merkle inclusion proof
3. Stolen valid token used without the device private key
4. Revoked-token reuse

Run them with:

```powershell
python -m pytest tests/test_security_attacks.py -q
```

The broader test suite also covers expired tokens, forged signatures, stale
timestamps, policy violations, epoch mismatch, public-key substitution and old
proof use after device revocation. Full explanations are provided in
`docs/SECURITY_EVALUATION.md`.
