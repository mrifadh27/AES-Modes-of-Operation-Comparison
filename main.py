"""
main.py
=======
Entry point for the PUSL2025 AES Modes of Operation experiment.

Execution Order
---------------
1. Correctness verification — confirms all four modes round-trip correctly
   and that GCM tamper detection raises ``ValueError`` on modified ciphertext.
2. ECB pattern-leakage demonstration — empirically shows that ECB reveals
   plaintext structure through ciphertext block equality.
3. Full benchmark — measures encryption time, decryption time, and throughput
   for ECB, CBC, CTR, and GCM across 1 KB, 10 KB, 100 KB, and 1 MB inputs.
4. Results table — prints a formatted console summary grouped by input size.
5. Figure generation — saves four PNG figures to the ``results/`` directory.
6. Result persistence — saves full data to ``results/results.csv`` and
   ``results/results.json``.

Usage
-----
Run from the project root directory::

    python main.py

Dependencies must be installed first::

    pip install -r requirements.txt

Output Files
------------
results/results.csv            — full numerical results in CSV format
results/results.json           — full numerical results in JSON format
results/fig1_encryption_time.png
results/fig2_throughput.png
results/fig3_decryption_time.png
results/fig4_security_summary.png
"""

import os
import sys

# ---------------------------------------------------------------------------
# Ensure the project root is on the Python path so that relative imports
# within subpackages resolve correctly regardless of the working directory.
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ---------------------------------------------------------------------------
# Ensure the results output directory exists
# ---------------------------------------------------------------------------
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Imports (after sys.path is set)
# ---------------------------------------------------------------------------
from benchmark.verification import verify_correctness, demonstrate_ecb_weakness
from benchmark.benchmark import run_experiment, save_csv, save_json, print_results_table
from plotting.plotting import generate_all_figures


def main() -> None:
    """Orchestrate the full AES experiment pipeline."""

    # ── Step 1: Verify correctness ────────────────────────────────────────
    all_passed = verify_correctness()
    if not all_passed:
        print("\n  ⚠  Aborting: correctness checks failed. Fix implementation before benchmarking.")
        sys.exit(1)

    # ── Step 2: ECB pattern-leakage demonstration ─────────────────────────
    demonstrate_ecb_weakness()

    # ── Step 3: Run full benchmark ────────────────────────────────────────
    results = run_experiment()

    # ── Step 4: Print formatted results table ─────────────────────────────
    print_results_table(results)

    # ── Step 5: Generate figures ──────────────────────────────────────────
    generate_all_figures(results)

    # ── Step 6: Persist results ───────────────────────────────────────────
    save_csv(results,  os.path.join(RESULTS_DIR, "results.csv"))
    save_json(results, os.path.join(RESULTS_DIR, "results.json"))

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 68)
    print("  EXPERIMENT COMPLETE")
    print("=" * 68)
    print("  Output files written to results/:")
    print("    results.csv                 — full numerical data")
    print("    results.json                — full numerical data (JSON)")
    print("    fig1_encryption_time.png    — Figure 1")
    print("    fig2_throughput.png         — Figure 2")
    print("    fig3_decryption_time.png    — Figure 3")
    print("    fig4_security_summary.png   — Figure 4")
    print("=" * 68 + "\n")


if __name__ == "__main__":
    main()
