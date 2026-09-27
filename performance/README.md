# Performance ownership

- Member 1: registration, batch construction, proof generation, batch approach.
- Member 2: verification, token validation, access latency, individual-update approach.
- Shared device counts: 5, 10, 25, 50, 100.
- Run each measurement 10 times with `time.perf_counter_ns()`.
- Store raw columns: `run_id,device_count,operation,latency_ms,success`.

