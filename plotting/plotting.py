import matplotlib
matplotlib.use("Agg")  # non-interactive backend — no display required
import matplotlib.pyplot as plt
import pandas as pd

from utils.helpers import MODES, INPUT_SIZES


# Consistent colour map across all figures


COLOURS: dict[str, str] = {
    "ECB": "#E74C3C",   # red   — signals insecurity
    "CBC": "#3498DB",   # blue
    "CTR": "#2ECC71",   # green
    "GCM": "#9B59B6",   # purple
}

SIZE_ORDER: list[str] = list(INPUT_SIZES.keys())  # ["1 KB", "10 KB", …]



# Internal helpers


def _ordered_dataframe(results: list[dict]) -> pd.DataFrame:
    """Return a DataFrame with ``data_size_label`` as an ordered Categorical."""
    df = pd.DataFrame(results)
    df["data_size_label"] = pd.Categorical(
        df["data_size_label"], categories=SIZE_ORDER, ordered=True
    )
    return df.sort_values("data_size_label")


# Figure 1 — Encryption Time


def plot_encryption_time(
    results: list[dict],
    output_path: str = "results/fig1_encryption_time.png",
) -> None:
    """
    Plot encryption time (ms) vs input size for all four modes.

    Error bars represent ±1 standard deviation across the five trials,
    illustrating measurement variability due to OS scheduling jitter.

    Parameters
    ----------
    results : list[dict]
        Result records from :func:`benchmark.benchmark.run_experiment`.
    output_path : str
        Destination path for the saved PNG file.
    """
    df = _ordered_dataframe(results)
    fig, ax = plt.subplots(figsize=(9, 5))

    for mode in MODES:
        mode_df = df[df["mode"] == mode]
        enc_ms = mode_df["enc_time_mean_s"] * 1000
        err_ms = mode_df["enc_time_stdev_s"] * 1000

        ax.plot(
            mode_df["data_size_label"], enc_ms,
            marker="o", linewidth=2, label=mode, color=COLOURS[mode],
        )
        ax.errorbar(
            mode_df["data_size_label"], enc_ms, yerr=err_ms,
            fmt="none", ecolor=COLOURS[mode], alpha=0.4, capsize=4,
        )

    ax.set_title(
        "Figure 1: AES Encryption Time vs Input Size",
        fontsize=13, fontweight="bold",
    )
    ax.set_xlabel("Input Size", fontsize=11)
    ax.set_ylabel("Encryption Time (ms)", fontsize=11)
    ax.legend(title="AES Mode", fontsize=10)
    ax.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    print(f"  [OK] Figure 1 → {output_path}")


# Figure 2 — Encryption Throughput


def plot_throughput(
    results: list[dict],
    output_path: str = "results/fig2_throughput.png",
) -> None:
    """
    Plot encryption throughput (MB/s) as a grouped bar chart.

    Enables direct side-by-side comparison of all four modes at each
    input size.

    Parameters
    ----------
    results : list[dict]
        Result records from :func:`benchmark.benchmark.run_experiment`.
    output_path : str
        Destination path for the saved PNG file.
    """
    df = _ordered_dataframe(results)
    x = range(len(SIZE_ORDER))
    bar_width = 0.2
    offsets = [-1.5, -0.5, 0.5, 1.5]

    fig, ax = plt.subplots(figsize=(10, 5))

    for i, mode in enumerate(MODES):
        mode_df = df[df["mode"] == mode]
        positions = [xi + offsets[i] * bar_width for xi in x]
        ax.bar(
            positions, mode_df["enc_throughput_MBps"],
            width=bar_width, label=mode, color=COLOURS[mode], alpha=0.85,
        )

    ax.set_title(
        "Figure 2: AES Encryption Throughput by Mode and Input Size",
        fontsize=13, fontweight="bold",
    )
    ax.set_xlabel("Input Size", fontsize=11)
    ax.set_ylabel("Throughput (MB/s)", fontsize=11)
    ax.set_xticks(list(x))
    ax.set_xticklabels(SIZE_ORDER)
    ax.legend(title="AES Mode", fontsize=10)
    ax.grid(True, axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    print(f"  [OK] Figure 2 → {output_path}")


# Figure 3 — Decryption Time


def plot_decryption_time(
    results: list[dict],
    output_path: str = "results/fig3_decryption_time.png",
) -> None:
    """
    Plot decryption time (ms) vs input size for all four modes.

    Reveals GCM's pronounced decryption overhead at 1 MB caused by
    software-based GHASH computation lacking CLMUL hardware acceleration.

    Parameters
    ----------
    results : list[dict]
        Result records from :func:`benchmark.benchmark.run_experiment`.
    output_path : str
        Destination path for the saved PNG file.
    """
    df = _ordered_dataframe(results)
    fig, ax = plt.subplots(figsize=(9, 5))

    for mode in MODES:
        mode_df = df[df["mode"] == mode]
        ax.plot(
            mode_df["data_size_label"],
            mode_df["dec_time_mean_s"] * 1000,
            marker="s", linewidth=2, linestyle="--",
            label=mode, color=COLOURS[mode],
        )

    ax.set_title(
        "Figure 3: AES Decryption Time vs Input Size",
        fontsize=13, fontweight="bold",
    )
    ax.set_xlabel("Input Size", fontsize=11)
    ax.set_ylabel("Decryption Time (ms)", fontsize=11)
    ax.legend(title="AES Mode", fontsize=10)
    ax.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    print(f"  [OK] Figure 3 → {output_path}")


# Figure 4 — Security Feature Scores


def plot_security_summary(
    output_path: str = "results/fig4_security_summary.png",
) -> None:
    """
    Plot a qualitative security feature comparison across all four modes.

    Scores (0–3 scale)
    ------------------
    0 = None, 1 = Weak, 2 = Moderate, 3 = Strong.

    Dimensions
    ----------
    Confidentiality, Integrity (Auth Tag), IV/Nonce Required,
    Parallelisable Encryption, No Padding Needed.

    Parameters
    ----------
    output_path : str
        Destination path for the saved PNG file.
    """
    categories = [
        "Confidentiality",
        "Integrity\n(Auth Tag)",
        "IV/Nonce\nRequired",
        "Parallelisable\n(Encrypt)",
        "No Padding\nNeeded",
    ]

    # Scores: 0=None, 1=Weak, 2=Moderate, 3=Strong
    scores: dict[str, list[int]] = {
        "ECB": [1, 0, 0, 3, 0],
        "CBC": [2, 0, 3, 0, 0],
        "CTR": [3, 0, 3, 3, 3],
        "GCM": [3, 3, 3, 3, 3],
    }

    x = range(len(categories))
    bar_width = 0.2
    offsets = [-1.5, -0.5, 0.5, 1.5]

    fig, ax = plt.subplots(figsize=(10, 5))

    for i, mode in enumerate(MODES):
        positions = [xi + offsets[i] * bar_width for xi in x]
        ax.bar(
            positions, scores[mode],
            width=bar_width, label=mode, color=COLOURS[mode], alpha=0.85,
        )

    ax.set_title(
        "Figure 4: Security Feature Score by AES Mode",
        fontsize=13, fontweight="bold",
    )
    ax.set_xlabel("Security Property", fontsize=11)
    ax.set_ylabel("Score (0 = None,  3 = Strong)", fontsize=11)
    ax.set_xticks(list(x))
    ax.set_xticklabels(categories, fontsize=9)
    ax.set_ylim(0, 3.5)
    ax.set_yticks([0, 1, 2, 3])
    ax.set_yticklabels(["None", "Weak", "Moderate", "Strong"])
    ax.legend(title="AES Mode", fontsize=10)
    ax.grid(True, axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    print(f"  [OK] Figure 4 → {output_path}")


# Convenience wrapper — generate all figures at once

def generate_all_figures(results: list[dict]) -> None:
    """
    Generate all four figures from *results*.

    Output files are written to the ``results/`` directory.

    Parameters
    ----------
    results : list[dict]
        Result records from :func:`benchmark.benchmark.run_experiment`.
    """
    print("\n" + "=" * 68)
    print("  GENERATING FIGURES")
    print("=" * 68)
    plot_encryption_time(results)
    plot_throughput(results)
    plot_decryption_time(results)
    plot_security_summary()
