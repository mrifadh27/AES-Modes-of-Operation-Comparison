# PUSL2025 — AES Modes of Operation: Experimental Investigation

**Module:** PUSL2025 — Security Architectures & Cryptography  
**Track:** A — AES Modes of Operation Comparison  
**Group:** G | University of Plymouth via NSBM Green University  

---

## Project Overview

This project implements a controlled experimental investigation comparing
four AES modes of operation:

| Mode | Full Name | Security Level |
|------|-----------|----------------|
| **ECB** | Electronic Codebook | ⚠ Insecure — pattern leakage |
| **CBC** | Cipher Block Chaining | Confidentiality only |
| **CTR** | Counter Mode | Confidentiality only |
| **GCM** | Galois/Counter Mode | ✅ AEAD — confidentiality + integrity |

The experiment measures **encryption time**, **decryption time**, and
**throughput (MB/s)** across four input sizes — 1 KB, 10 KB, 100 KB,
and 1 MB — using AES-256 keys and the PyCryptodome production-grade
cryptographic library.

A structured **ECB pattern-leakage demonstration** empirically confirms
that ECB reveals plaintext structure through ciphertext block equality,
without requiring knowledge of the key.

---

## Project Structure

```
aes_project/
│
├── main.py                        # Entry point — run this file
│
├── crypto/                        # AES encryption implementations
│   ├── __init__.py
│   ├── ecb.py                     # AES-ECB encrypt / decrypt
│   ├── cbc.py                     # AES-CBC encrypt / decrypt
│   ├── ctr.py                     # AES-CTR encrypt / decrypt
│   └── gcm.py                     # AES-GCM encrypt / decrypt (AEAD)
│
├── benchmark/                     # Timing and verification logic
│   ├── __init__.py
│   ├── benchmark.py               # Benchmarking engine + result persistence
│   └── verification.py            # Correctness checks + ECB demo
│
├── plotting/                      # Visualisation
│   ├── __init__.py
│   └── plotting.py                # All four figures (matplotlib)
│
├── utils/                         # Shared utilities
│   ├── __init__.py
│   └── helpers.py                 # Key/IV/nonce generation, constants
│
├── results/                       # Auto-created on first run
│   ├── results.csv
│   ├── results.json
│   ├── fig1_encryption_time.png
│   ├── fig2_throughput.png
│   ├── fig3_decryption_time.png
│   └── fig4_security_summary.png
│
├── requirements.txt
└── README.md
```

---

## Installation

### Prerequisites

- Python 3.10 or higher
- pip

### Install dependencies

```bash
pip install -r requirements.txt
```

This installs:

| Package | Purpose |
|---------|---------|
| `pycryptodome` | AES encryption (ECB, CBC, CTR, GCM) with AES-NI hardware acceleration |
| `pandas` | Results aggregation and DataFrame operations |
| `matplotlib` | Figure generation |
| `tabulate` | Console table formatting |

---

## How to Run

From the project root directory:

```bash
python main.py
```

That's it. The script runs the full pipeline automatically.

---

## What Happens When You Run It

The experiment runs in six sequential steps:

```
Step 1 — Correctness Verification
        All four modes are tested with round-trip encrypt → decrypt across
        message sizes of 17, 1 024, and 102 400 bytes.
        GCM tamper detection is verified (ValueError on modified ciphertext).
        13 assertions must all pass before benchmarking begins.

Step 2 — ECB Pattern Leakage Demonstration
        A 96-byte structured plaintext with repeating 16-byte blocks is
        encrypted with ECB and CBC. The console output shows that ECB
        produces identical ciphertext blocks for identical plaintext blocks,
        while CBC produces entirely distinct blocks.

Step 3 — Full Benchmark
        80 timed measurements: 4 modes × 4 sizes × 5 trials.
        Timing uses time.perf_counter() at sub-microsecond resolution.
        Key / IV / nonce generation is excluded from the timing window.

Step 4 — Results Table
        Formatted console summary grouped by input size.

Step 5 — Figure Generation
        Four PNG figures saved to results/.

Step 6 — Result Persistence
        results.csv and results.json saved to results/.
```

---

## Output Files

| File | Description |
|------|-------------|
| `results/results.csv` | Full numerical results — all 16 conditions, mean ± stdev |
| `results/results.json` | Same data in JSON format |
| `results/fig1_encryption_time.png` | Encryption time vs input size (line + error bars) |
| `results/fig2_throughput.png` | Encryption throughput grouped bar chart |
| `results/fig3_decryption_time.png` | Decryption time vs input size |
| `results/fig4_security_summary.png` | Qualitative security feature score comparison |

---

## Experimental Parameters

| Parameter | Value | Justification |
|-----------|-------|---------------|
| Key size | 256 bits (AES-256) | Maximum security margin; relevant to healthcare / financial data |
| Block size | 128 bits | Fixed by AES specification (FIPS 197) |
| Input sizes | 1 KB, 10 KB, 100 KB, 1 MB | Covers IoT messages through enterprise documents |
| Trials per condition | 5 | Suppresses OS scheduling jitter; mean + stdev reported |
| Timing | `time.perf_counter()` | Sub-microsecond resolution; immune to clock adjustments |
| Plaintext | `os.urandom()` | Cryptographically random — eliminates data-dependent bias |
| GCM nonce | 96-bit | Per NIST SP 800-38D recommendation |
| GCM tag | 128-bit | Maximum length; 2⁻¹²⁸ forgery probability |

---

## Key Findings

| Mode | Enc Throughput @ 1 MB | Security |
|------|----------------------|---------|
| ECB | 1 015 MB/s | ⚠ Pattern leakage — DO NOT USE |
| CBC | 417 MB/s | Confidentiality; no integrity; padding oracle risk |
| CTR | 629 MB/s | Confidentiality; no integrity; bit-flip attack possible |
| **GCM** | **532 MB/s** | ✅ AEAD — confidentiality + integrity; TLS 1.3 mandated |

**Recommendation:** Use AES-256-GCM for all new systems requiring
confidentiality and integrity. GCM is only 15% slower than CTR at 1 MB
while providing complete authenticated encryption.
