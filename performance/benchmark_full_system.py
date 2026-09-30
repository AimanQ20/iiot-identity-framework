"""Reproducible benchmark for the final integrated IIoT implementation.

Run from the repository root:
    python -m performance.benchmark_full_system

The benchmark uses the project's real ECC, JWT, Merkle and verification
functions. It uses an isolated in-memory SQLite database and never modifies
the demonstration database in data/iiot.db.
"""

from __future__ import annotations

import csv
import statistics
import time
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from devices.device import SimulatedDevice
from fog.database import Base
from fog.merkle import build_merkle_root, generate_inclusion_proof, verify_inclusion_proof
from fog.models import Device
from fog.registration import create_device_leaf
from fog.schemas import AuthenticatedDevice
from fog.token_service import issue_temporary_token, validate_temporary_token


DEVICE_COUNTS = [5, 10, 25, 50, 100, 200]
REPETITIONS = 5
RESULTS_DIR = Path("performance/results")
RAW_FILE = RESULTS_DIR / "full_system_raw.csv"
SUMMARY_FILE = RESULTS_DIR / "full_system_summary.csv"


def isolated_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def timed(callable_):
    start = time.perf_counter_ns()
    value = callable_()
    return value, (time.perf_counter_ns() - start) / 1_000_000


def authenticated_payload(device: SimulatedDevice) -> AuthenticatedDevice:
    return AuthenticatedDevice(
        device_id=device.device_id,
        did=device.did,
        public_key=device.public_key_pem,
        public_key_thumbprint=device.public_key_thumbprint,
        device_type=device.device_type,
        role=device.role,
        zone=device.zone,
        authentication_complete=True,
        proof_of_possession_verified=True,
        status="PENDING",
    )


def run_once(device_count: int, run_id: int) -> list[dict]:
    devices = [
        SimulatedDevice(
            f"BENCH-{run_id}-{i:04d}",
            "temperature_sensor",
            psk=f"benchmark-secret-{i}",
        )
        for i in range(device_count)
    ]

    registration_times = []
    registration_start = time.perf_counter_ns()
    for device in devices:
        _, elapsed = timed(lambda d=device: (
            d.create_psk_response(f"nonce-{d.device_id}"),
            d.sign_challenge(f"challenge-{d.device_id}"),
            create_device_leaf(d.did, d.public_key_pem),
        ))
        registration_times.append(elapsed)
    registration_total_s = (time.perf_counter_ns() - registration_start) / 1_000_000_000

    leaves = [create_device_leaf(d.did, d.public_key_pem) for d in devices]
    root, batch_ms = timed(lambda: build_merkle_root(leaves))

    proof_times = []
    verification_times = []
    proof_sizes = []
    for leaf in leaves:
        proof, proof_ms = timed(lambda current=leaf: generate_inclusion_proof(leaves, current))
        valid, verify_ms = timed(lambda current=leaf, path=proof: verify_inclusion_proof(current, path, root))
        assert valid
        proof_times.append(proof_ms)
        verification_times.append(verify_ms)
        proof_sizes.append(sum(32 + 1 for _ in proof))

    db = isolated_session()
    token_issue_times = []
    token_validation_times = []
    try:
        # Limit database/JWT measurement to at most 50 devices per run so the
        # benchmark remains quick while still exercising the real services.
        for device in devices[: min(device_count, 50)]:
            db.add(Device(
                device_id=device.device_id, did=device.did,
                public_key=device.public_key_pem,
                public_key_thumbprint=device.public_key_thumbprint,
                device_type=device.device_type, role=device.role,
                zone=device.zone, status="PENDING",
                authentication_complete=True, pop_verified=True,
            ))
            db.commit()
            token_result, issue_ms = timed(
                lambda d=device: issue_temporary_token(authenticated_payload(d), db)
            )
            token = token_result[0]
            payload, validation_ms = timed(lambda t=token: validate_temporary_token(t, db))
            assert payload["sub"] == device.did
            token_issue_times.append(issue_ms)
            token_validation_times.append(validation_ms)
    finally:
        db.close()

    return [
        {
            "run_id": run_id,
            "device_count": device_count,
            "registration_latency_ms": statistics.mean(registration_times),
            "registration_throughput_per_second": device_count / registration_total_s,
            "batch_time_ms": batch_ms,
            "proof_generation_ms": statistics.mean(proof_times),
            "proof_verification_ms": statistics.mean(verification_times),
            "verification_throughput_per_second": 1000 / statistics.mean(verification_times),
            "token_issue_ms": statistics.mean(token_issue_times),
            "token_validation_ms": statistics.mean(token_validation_times),
            "proof_size_bytes": statistics.mean(proof_sizes),
        }
    ]


def create_outputs(rows: list[dict]) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with RAW_FILE.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    raw = pd.DataFrame(rows)
    summary = raw.groupby("device_count", as_index=False).agg(
        registration_latency_ms=("registration_latency_ms", "mean"),
        registration_throughput_per_second=("registration_throughput_per_second", "mean"),
        batch_time_ms=("batch_time_ms", "mean"),
        proof_generation_ms=("proof_generation_ms", "mean"),
        proof_verification_ms=("proof_verification_ms", "mean"),
        verification_throughput_per_second=("verification_throughput_per_second", "mean"),
        token_issue_ms=("token_issue_ms", "mean"),
        token_validation_ms=("token_validation_ms", "mean"),
        proof_size_bytes=("proof_size_bytes", "mean"),
    )
    summary.to_csv(SUMMARY_FILE, index=False)

    sns.set_theme(style="whitegrid")
    charts = [
        ("registration_latency_ms", "Registration latency", "Mean latency (ms)", "registration_latency.png"),
        ("batch_time_ms", "Merkle batch-processing time", "Mean time (ms)", "merkle_batch_time.png"),
        ("proof_verification_ms", "Merkle proof-verification latency", "Mean latency (ms)", "verification_latency.png"),
        ("verification_throughput_per_second", "Proof-verification throughput", "Verifications/second", "verification_throughput.png"),
    ]
    for metric, title, y_label, filename in charts:
        plt.figure(figsize=(8, 5))
        sns.lineplot(data=summary, x="device_count", y=metric, marker="o")
        plt.title(title)
        plt.xlabel("Number of devices")
        plt.ylabel(y_label)
        plt.tight_layout()
        plt.savefig(RESULTS_DIR / filename, dpi=300)
        plt.close()


def main() -> None:
    rows = []
    print("Running integrated IIoT benchmark")
    for count in DEVICE_COUNTS:
        print(f"  devices={count}")
        for run_id in range(1, REPETITIONS + 1):
            rows.extend(run_once(count, run_id))
    create_outputs(rows)
    print(f"Raw measurements: {RAW_FILE}")
    print(f"Summary: {SUMMARY_FILE}")
    print(f"Graphs: {RESULTS_DIR}")


if __name__ == "__main__":
    main()
