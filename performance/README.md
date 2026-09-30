# Performance Evaluation

Run the final-system benchmark from the repository root:

```powershell
python -m performance.benchmark_full_system
```

It measures the real project functions for ECC onboarding operations, Merkle
batch construction, inclusion-proof generation and verification, JWT issuance
and validation, throughput, and proof size.

- Device counts: 5, 10, 25, 50, 100, 200
- Repetitions: 5
- Timer: `time.perf_counter_ns()`
- Database: isolated in-memory SQLite; demonstration data is not modified

Generated evidence is saved under `performance/results/`:

- `full_system_raw.csv`
- `full_system_summary.csv`
- `registration_latency.png`
- `merkle_batch_time.png`
- `verification_latency.png`
- `verification_throughput.png`

`benchmark_phase1.py` is retained as the original Phase 1 microbenchmark.
