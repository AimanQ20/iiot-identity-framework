# Group Contributions

The group retained one canonical FastAPI implementation and integrated each
member's work at the service, evaluation and documentation layers. A second
incompatible backend was not copied into the submission because that would
have created duplicate device, fog and frontend implementations.

| Member | Primary contribution |
|---|---|
| Member 1 | Phase 1 authentication and registration, P-256 device simulator, DID/leaf generation, deterministic Merkle batching, inclusion proofs, integration and Streamlit workflow |
| Member 2 | Phase 2 JWT issuance and provisional authorization, Phase 3 permanent proof access, policy enforcement, token/device revocation, integration tests |
| Member 3 | Security-attack methodology, replay and stolen-token threat analysis, performance/scalability methodology, benchmark metrics and evaluation documentation |

## Integration decisions

Ideas adopted from Member 3's independent prototype:

- Repeat benchmarks over device counts `5, 10, 25, 50, 100, 200`.
- Measure registration, batching, proof generation, proof verification, token
  issuance/validation, throughput and proof size.
- Explicitly test replay, proof tampering, stolen tokens and expired/revoked
  credentials.
- Report which security component detects each attack.
- Emphasize identity-versus-authorization and historical-proof-versus-current-
  revocation distinctions.

These ideas were reimplemented against the canonical FastAPI/SQLite code so
that all results describe the submitted system. Member 3's separate in-memory
`FogNode`, custom tokens and Flask frontend were not copied.

Replace `Member 1`, `Member 2` and `Member 3` with the students' names and IDs
before submission if the instructor requires named contribution records.
