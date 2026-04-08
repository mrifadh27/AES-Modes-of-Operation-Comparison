import os
import csv
import json
import statistics
import time
from typing import Any

import crypto.ecb as ecb
import crypto.cbc as cbc
import crypto.ctr as ctr
import crypto.gcm as gcm

from utils.helpers import (
    KEY_SIZE_BYTES,
    NUM_TRIALS,
    MODES,
    INPUT_SIZES,
    bytes_to_label,
    generate_key,
    generate_iv,
    generate_nonce_ctr,
    generate_nonce_gcm,
)


# Core benchmarking function


def benchmark_mode(
    mode: str,
    plaintext: bytes,
    key: bytes,
    trials: int = NUM_TRIALS,
) -> dict[str, Any]:
   
    if mode not in MODES:
        raise ValueError(f"Unsupported mode '{mode}'. Choose from: {MODES}")

    enc_times: list[float] = []
    dec_times: list[float] = []
    data_size: int = len(plaintext)

    for _ in range(trials):
        if mode == "ECB":
            t0 = time.perf_counter()
            ct = ecb.encrypt(plaintext, key)
            enc_times.append(time.perf_counter() - t0)

            t0 = time.perf_counter()
            ecb.decrypt(ct, key)
            dec_times.append(time.perf_counter() - t0)

        elif mode == "CBC":
            # IV is generated inside encrypt(); exclude from outer timing
            t0 = time.perf_counter()
            ct, iv = cbc.encrypt(plaintext, key)
            enc_times.append(time.perf_counter() - t0)

            t0 = time.perf_counter()
            cbc.decrypt(ct, key, iv)
            dec_times.append(time.perf_counter() - t0)

        elif mode == "CTR":
            t0 = time.perf_counter()
            ct, nonce = ctr.encrypt(plaintext, key)
            enc_times.append(time.perf_counter() - t0)

            t0 = time.perf_counter()
            ctr.decrypt(ct, key, nonce)
            dec_times.append(time.perf_counter() - t0)

        elif mode == "GCM":
            t0 = time.perf_counter()
            ct, nonce, tag = gcm.encrypt(plaintext, key)
            enc_times.append(time.perf_counter() - t0)

            # Tag verification is included in decryption timing — it is an
            # inseparable component of authenticated decryption and cannot
            # be omitted in any real deployment.
            t0 = time.perf_counter()
            gcm.decrypt(ct, key, nonce, tag)
            dec_times.append(time.perf_counter() - t0)

    mean_enc = statistics.mean(enc_times)
    mean_dec = statistics.mean(dec_times)
    stdev_enc = statistics.stdev(enc_times) if trials > 1 else 0.0
    stdev_dec = statistics.stdev(dec_times) if trials > 1 else 0.0

    mib = 1024 * 1024
    enc_throughput = data_size / mean_enc / mib if mean_enc > 0 else 0.0
    dec_throughput = data_size / mean_dec / mib if mean_dec > 0 else 0.0

    return {
        "mode":               mode,
        "data_size_bytes":    data_size,
        "data_size_label":    bytes_to_label(data_size),
        "trials":             trials,
        "enc_time_mean_s":    round(mean_enc,   8),
        "enc_time_stdev_s":   round(stdev_enc,  8),
        "dec_time_mean_s":    round(mean_dec,   8),
        "dec_time_stdev_s":   round(stdev_dec,  8),
        "enc_throughput_MBps": round(enc_throughput, 4),
        "dec_throughput_MBps": round(dec_throughput, 4),
    }



# Full experiment runner


def run_experiment(trials: int = NUM_TRIALS) -> list[dict[str, Any]]:
    """
    Run the complete benchmark across all modes and input sizes.

    Iterates over every (mode × size) combination defined in
    :data:`utils.helpers.INPUT_SIZES` and :data:`utils.helpers.MODES`,
    collecting performance metrics for each pair.

    Parameters
    ----------
    trials : int
        Number of timing repetitions per condition (default: ``NUM_TRIALS``).

    Returns
    -------
    list[dict[str, Any]]
        List of result records — one per (mode × size) combination.
    """
    print("=" * 68)
    print("  PUSL2025 — AES Modes of Operation Experimental Investigation")
    print("=" * 68)
    print(f"\n  Key Size  : {KEY_SIZE_BYTES * 8} bits (AES-256)")
    print(f"  Trials    : {trials} per (mode × size)")
    print(f"  Modes     : {', '.join(MODES)}")
    print(f"  Sizes     : {', '.join(INPUT_SIZES)}\n")

    key = generate_key()
    all_results: list[dict[str, Any]] = []

    for size_label, size_bytes in INPUT_SIZES.items():
        plaintext = os.urandom(size_bytes)
        print(f"  Testing: {size_label} ({size_bytes:,} bytes)")

        for mode in MODES:
            result = benchmark_mode(mode, plaintext, key, trials)
            all_results.append(result)
            print(
                f"    [{mode:>3}]  "
                f"Enc: {result['enc_time_mean_s'] * 1000:8.4f} ms  "
                f"Dec: {result['dec_time_mean_s'] * 1000:8.4f} ms  "
                f"Throughput: {result['enc_throughput_MBps']:8.2f} MB/s"
            )
        print()

    return all_results


# Persistence helpers


def save_csv(results: list[dict[str, Any]], filepath: str) -> None:
    """
    Persist *results* to a CSV file at *filepath*.

    Parameters
    ----------
    results : list[dict[str, Any]]
        Result records produced by :func:`run_experiment`.
    filepath : str
        Destination path, e.g. ``'results/results.csv'``.
    """
    if not results:
        return
    fieldnames = list(results[0].keys())
    with open(filepath, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"  [OK] CSV  → {filepath}")


def save_json(results: list[dict[str, Any]], filepath: str) -> None:
    """
    Persist *results* to a JSON file at *filepath*.

    Parameters
    ----------
    results : list[dict[str, Any]]
        Result records produced by :func:`run_experiment`.
    filepath : str
        Destination path, e.g. ``'results/results.json'``.
    """
    with open(filepath, "w") as fh:
        json.dump(results, fh, indent=2)
    print(f"  [OK] JSON → {filepath}")


# Console display


def print_results_table(results: list[dict[str, Any]]) -> None:
    """
    Print all benchmark results grouped by input size.

    Parameters
    ----------
    results : list[dict[str, Any]]
        Result records produced by :func:`run_experiment`.
    """
    try:
        import pandas as pd
        from tabulate import tabulate
    except ImportError:
        print("pandas and tabulate required for table display.")
        return

    print("\n" + "=" * 68)
    print("  RESULTS SUMMARY")
    print("=" * 68)

    df = pd.DataFrame(results)

    for size_label in INPUT_SIZES:
        subset = df[df["data_size_label"] == size_label].copy()
        subset = subset[[
            "mode",
            "enc_time_mean_s",
            "dec_time_mean_s",
            "enc_throughput_MBps",
            "dec_throughput_MBps",
        ]]
        subset.columns = [
            "Mode",
            "Enc Time (s)",
            "Dec Time (s)",
            "Enc Throughput (MB/s)",
            "Dec Throughput (MB/s)",
        ]
        print(f"\n  Input Size: {size_label}")
        print(tabulate(subset, headers="keys", tablefmt="grid",
                       showindex=False, floatfmt=".6f"))
