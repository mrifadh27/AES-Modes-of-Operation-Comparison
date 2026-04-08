"""
benchmark/verification.py
=========================
Correctness verification and ECB pattern-leakage demonstration.

These routines are executed **before** any benchmarking to ensure that
all four AES mode implementations produce correct round-trip results.
Running verification first prevents benchmarking silent failures where
a bug causes fast but incorrect output.

Functions
---------
verify_correctness
    Round-trip encrypt-decrypt assertions for all four modes across
    multiple message sizes, plus GCM tamper-detection check.
demonstrate_ecb_weakness
    Constructs a structured plaintext with repeating 16-byte blocks and
    shows that ECB ciphertext reveals the repetitions — empirical evidence
    of the ECB Penguin vulnerability.
"""

import os
from collections import Counter

import crypto.ecb as ecb
import crypto.cbc as cbc
import crypto.ctr as ctr
import crypto.gcm as gcm
from utils.helpers import generate_key, generate_iv, BLOCK_SIZE


# ---------------------------------------------------------------------------
# Correctness verification
# ---------------------------------------------------------------------------

def verify_correctness() -> bool:
    """
    Assert that all four AES modes correctly round-trip encrypt and decrypt.

    Tests run against three message sizes: 17 bytes (non-block-aligned),
    1 024 bytes (1 KB), and 102 400 bytes (100 KB).  GCM tamper detection
    is also verified by flipping one ciphertext byte and confirming that
    ``ValueError`` is raised.

    Returns
    -------
    bool
        ``True`` if all assertions pass.

    Raises
    ------
    AssertionError
        If any round-trip produces incorrect output.
    """
    print("\n" + "=" * 68)
    print("  CORRECTNESS VERIFICATION")
    print("=" * 68)

    key = generate_key()
    test_sizes = [17, 1024, 100 * 1024]
    all_passed = True

    for size in test_sizes:
        msg = os.urandom(size)
        label = f"{size:,} bytes"

        # ECB
        ct = ecb.encrypt(msg, key)
        assert ecb.decrypt(ct, key) == msg, f"ECB round-trip FAILED for {label}"

        # CBC
        ct, iv = cbc.encrypt(msg, key)
        assert cbc.decrypt(ct, key, iv) == msg, f"CBC round-trip FAILED for {label}"

        # CTR
        ct, nonce = ctr.encrypt(msg, key)
        assert ctr.decrypt(ct, key, nonce) == msg, f"CTR round-trip FAILED for {label}"

        # GCM
        ct, nonce, tag = gcm.encrypt(msg, key)
        assert gcm.decrypt(ct, key, nonce, tag) == msg, f"GCM round-trip FAILED for {label}"

        print(f"  ✓  All modes passed round-trip for {label}")

    # GCM tamper-detection
    ct, nonce, tag = gcm.encrypt(b"Sensitive patient record 12345678", key)
    tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
    try:
        gcm.decrypt(tampered, key, nonce, tag)
        print("  ✗  GCM tamper detection FAILED (no exception raised)")
        all_passed = False
    except ValueError:
        print("  ✓  GCM tamper detection PASSED (ValueError on modified ciphertext)")

    status = "All checks passed." if all_passed else "One or more checks FAILED."
    print(f"\n  {status}\n")
    return all_passed


# ---------------------------------------------------------------------------
# ECB pattern-leakage demonstration
# ---------------------------------------------------------------------------

def demonstrate_ecb_weakness() -> dict:
    """
    Empirically demonstrate ECB's pattern-leakage (ECB Penguin) vulnerability.

    A 96-byte structured plaintext is constructed from six 16-byte blocks
    with intentional repetition — simulating realistic bank transaction
    records.  ECB encryption of this plaintext produces identical ciphertext
    blocks wherever the plaintext blocks are identical, directly revealing
    data structure without key knowledge.

    The same plaintext is encrypted with CBC for comparison: CBC produces
    six entirely distinct ciphertext blocks due to its chaining mechanism.

    Returns
    -------
    dict
        ``{'ecb_blocks': list[str], 'ecb_repeated_count': int}``
    """
    print("\n" + "=" * 68)
    print("  ECB PATTERN LEAKAGE DEMONSTRATION")
    print("=" * 68)

    # Each segment is exactly 16 bytes (one AES block)
    block_a = b"ACCOUNT:00012345"   # bank account record
    block_b = b"AMOUNT: $1000.00"   # transaction amount
    block_c = b"STATUS: APPROVED"   # status flag

    # Structured plaintext with repeating blocks
    plaintext = block_a + block_b + block_a + block_c + block_a + block_b

    assert len(plaintext) % BLOCK_SIZE == 0, "Plaintext must be block-aligned"

    key = generate_key()

    # ECB
    ct_ecb = ecb.encrypt(plaintext, key)

    # CBC (random IV)
    ct_cbc, _ = cbc.encrypt(plaintext, key)

    # Split into 16-byte blocks
    n_blocks = len(plaintext) // BLOCK_SIZE

    print("\n  Plaintext blocks (each 16 bytes):")
    for i in range(n_blocks):
        blk = plaintext[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE]
        repeat_flag = "  ← REPEATING" if plaintext.count(blk) > 1 else ""
        print(f"    Block {i}: {blk.decode()}{repeat_flag}")

    ecb_hex_blocks: list[str] = [
        ct_ecb[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE].hex()
        for i in range(n_blocks)
    ]

    print("\n  ECB ciphertext blocks:")
    for i, blk_hex in enumerate(ecb_hex_blocks):
        print(f"    Block {i}: {blk_hex}")

    print("\n  CBC ciphertext blocks (comparison):")
    for i in range(n_blocks):
        blk_hex = ct_cbc[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE].hex()
        print(f"    Block {i}: {blk_hex}")

    # Detect repeating ECB blocks
    counts = Counter(ecb_hex_blocks)
    repeated = {blk: cnt for blk, cnt in counts.items() if cnt > 1}
    repeated_count = len(repeated)

    print("\n  Pattern Analysis:")
    if repeated:
        print(f"  ⚠  WARNING: {repeated_count} repeated ciphertext block(s) in ECB output!")
        print("     An attacker can identify identical plaintext blocks WITHOUT the key.\n")
        for blk_hex, cnt in repeated.items():
            print(f"     {blk_hex[:32]}…  appears {cnt} times")
    else:
        print("  No repeating blocks detected.")

    print("\n  CONCLUSION: ECB must NEVER be used for structured or sensitive data.")
    print("  CBC, CTR, and GCM eliminate this vulnerability through chaining,")
    print("  counter modes, or randomised nonces.\n")

    return {"ecb_blocks": ecb_hex_blocks, "ecb_repeated_count": repeated_count}
