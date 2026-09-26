"""Phase 1 performance and scalability benchmark."""

import csv
import hashlib
import statistics
import time
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

from devices.device import SimulatedDevice
from fog.merkle import (
    build_merkle_root,
    generate_inclusion_proof,
)
from fog.registration import create_device_leaf


DEVICE_COUNTS = [5, 10, 25, 50, 100]
REPETITIONS = 10

RESULTS_DIRECTORY = Path("performance/results")
RAW_RESULTS_FILE = RESULTS_DIRECTORY / "member1_raw.csv"
SUMMARY_FILE = RESULTS_DIRECTORY / "member1_summary.csv"


def create_devices(device_count: int):
    return [
        SimulatedDevice(
            device_id=f"BENCH-{index:04d}",
            device_type="temperature_sensor",
            psk=f"benchmark-secret-{index}",
        )
        for index in range(device_count)
    ]


def measure_registration(device: SimulatedDevice) -> float:
    """Measure cryptographic onboarding operations."""

    start = time.perf_counter_ns()

    # Device creates PSK authentication response.
    nonce = f"benchmark-nonce-{device.device_id}"
    device.create_psk_response(nonce)

    # Fog calculates device leaf.
    create_device_leaf(
        device.did,
        device.public_key_pem,
    )

    # Device performs proof-of-possession signing.
    device.sign_challenge(
        f"benchmark-challenge-{device.device_id}"
    )

    end = time.perf_counter_ns()

    return (end - start) / 1_000_000


def benchmark_one_run(
    device_count: int,
    run_id: int,
) -> list[dict]:
    devices = create_devices(device_count)
    results = []

    registration_start = time.perf_counter_ns()

    registration_latencies = [
        measure_registration(device)
        for device in devices
    ]

    registration_end = time.perf_counter_ns()

    total_registration_seconds = (
        registration_end - registration_start
    ) / 1_000_000_000

    throughput = (
        device_count / total_registration_seconds
        if total_registration_seconds > 0
        else 0
    )

    leaves = [
        create_device_leaf(
            device.did,
            device.public_key_pem,
        )
        for device in devices
    ]

    batch_start = time.perf_counter_ns()
    root = build_merkle_root(leaves)
    batch_end = time.perf_counter_ns()

    batch_time_ms = (
        batch_end - batch_start
    ) / 1_000_000

    proof_latencies = []
    proof_sizes = []

    for leaf in leaves:
        proof_start = time.perf_counter_ns()

        proof = generate_inclusion_proof(
            leaves,
            leaf,
        )

        proof_end = time.perf_counter_ns()

        proof_latencies.append(
            (proof_end - proof_start) / 1_000_000
        )

        proof_sizes.append(
            sum(
                len(bytes.fromhex(item["hash"])) + 1
                for item in proof
            )
        )

    results.extend(
        [
            {
                "run_id": run_id,
                "device_count": device_count,
                "operation": "average_registration_latency",
                "latency_ms": statistics.mean(
                    registration_latencies
                ),
                "throughput_per_second": throughput,
                "proof_size_bytes": "",
                "success": True,
            },
            {
                "run_id": run_id,
                "device_count": device_count,
                "operation": "batch_processing",
                "latency_ms": batch_time_ms,
                "throughput_per_second": "",
                "proof_size_bytes": "",
                "success": bool(root),
            },
            {
                "run_id": run_id,
                "device_count": device_count,
                "operation": "average_proof_generation",
                "latency_ms": statistics.mean(
                    proof_latencies
                ),
                "throughput_per_second": "",
                "proof_size_bytes": statistics.mean(
                    proof_sizes
                ),
                "success": True,
            },
        ]
    )

    return results


def save_raw_results(results: list[dict]) -> None:
    RESULTS_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "run_id",
        "device_count",
        "operation",
        "latency_ms",
        "throughput_per_second",
        "proof_size_bytes",
        "success",
    ]

    with RAW_RESULTS_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(results)


def create_summary_and_graphs() -> None:
    data = pd.read_csv(RAW_RESULTS_FILE)

    summary = (
        data.groupby(
            ["device_count", "operation"],
            as_index=False,
        )
        .agg(
            mean_latency_ms=("latency_ms", "mean"),
            standard_deviation_ms=("latency_ms", "std"),
            mean_throughput=(
                "throughput_per_second",
                "mean",
            ),
            mean_proof_size=(
                "proof_size_bytes",
                "mean",
            ),
        )
    )

    summary.to_csv(
        SUMMARY_FILE,
        index=False,
    )

    sns.set_theme(style="whitegrid")

    batch_data = summary[
        summary["operation"] == "batch_processing"
    ]

    plt.figure(figsize=(8, 5))
    sns.lineplot(
        data=batch_data,
        x="device_count",
        y="mean_latency_ms",
        marker="o",
    )
    plt.title(
        "Number of Devices vs Batch-Processing Time"
    )
    plt.xlabel("Number of Devices")
    plt.ylabel("Mean Batch Time (ms)")
    plt.tight_layout()
    plt.savefig(
        RESULTS_DIRECTORY / "batch_processing_time.png",
        dpi=300,
    )
    plt.close()

    registration_data = summary[
        summary["operation"]
        == "average_registration_latency"
    ]

    plt.figure(figsize=(8, 5))
    sns.lineplot(
        data=registration_data,
        x="device_count",
        y="mean_latency_ms",
        marker="o",
    )
    plt.title(
        "Number of Devices vs Registration Latency"
    )
    plt.xlabel("Number of Devices")
    plt.ylabel("Mean Registration Latency (ms)")
    plt.tight_layout()
    plt.savefig(
        RESULTS_DIRECTORY / "registration_latency.png",
        dpi=300,
    )
    plt.close()

    plt.figure(figsize=(8, 5))
    sns.lineplot(
        data=registration_data,
        x="device_count",
        y="mean_throughput",
        marker="o",
    )
    plt.title(
        "Number of Devices vs Registration Throughput"
    )
    plt.xlabel("Number of Devices")
    plt.ylabel("Registrations per Second")
    plt.tight_layout()
    plt.savefig(
        RESULTS_DIRECTORY / "registration_throughput.png",
        dpi=300,
    )
    plt.close()


def main():
    all_results = []

    print("Starting Phase 1 performance benchmark")

    for device_count in DEVICE_COUNTS:
        print(f"Testing {device_count} devices...")

        for run_id in range(1, REPETITIONS + 1):
            all_results.extend(
                benchmark_one_run(
                    device_count,
                    run_id,
                )
            )

    save_raw_results(all_results)
    create_summary_and_graphs()

    print("\nBenchmark complete")
    print(f"Raw results: {RAW_RESULTS_FILE}")
    print(f"Summary: {SUMMARY_FILE}")
    print(f"Graphs: {RESULTS_DIRECTORY}")


if __name__ == "__main__":
    main()