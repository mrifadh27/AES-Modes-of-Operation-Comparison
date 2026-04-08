from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Constants


KEY_SIZE_BYTES: int = 32          # AES-256
BLOCK_SIZE: int = AES.block_size  # 16 bytes — fixed by AES spec

INPUT_SIZES: dict[str, int] = {
    "1 KB":   1 * 1024,
    "10 KB":  10 * 1024,
    "100 KB": 100 * 1024,
    "1 MB":   1 * 1024 * 1024,
}

NUM_TRIALS: int = 5

MODES: list[str] = ["ECB", "CBC", "CTR", "GCM"]


# Key & randomness generation


def generate_key() -> bytes:
    """
    Generate a cryptographically secure 256-bit (32-byte) AES key.

    Returns
    -------
    bytes
        32 random bytes suitable for use as an AES-256 key.
    """
    return get_random_bytes(KEY_SIZE_BYTES)


def generate_iv() -> bytes:
    """
    Generate a random 128-bit (16-byte) Initialisation Vector for CBC mode.

    The IV must be unique per encryption operation to guarantee semantic
    security (IND-CPA).  It does not need to be secret and is typically
    prepended to the ciphertext.

    Returns
    -------
    bytes
        16 random bytes.
    """
    return get_random_bytes(BLOCK_SIZE)


def generate_nonce_ctr() -> bytes:
    """
    Generate a random 64-bit (8-byte) nonce for CTR mode.

    PyCryptodome's CTR implementation combines this nonce with an internal
    counter to form the full 128-bit counter block.  The nonce must never
    be reused with the same key — reuse allows an attacker to XOR two
    ciphertexts and recover the XOR of the plaintexts.

    Returns
    -------
    bytes
        8 random bytes.
    """
    return get_random_bytes(8)


def generate_nonce_gcm() -> bytes:
    """
    Generate a random 96-bit (12-byte) nonce for GCM mode.

    NIST SP 800-38D recommends 96-bit nonces for GCM as the optimal length,
    balancing collision resistance (birthday bound ≈ 2^32 encryptions per
    key) with simplicity of the counter construction.

    Returns
    -------
    bytes
        12 random bytes.
    """
    return get_random_bytes(12)

# Formatting utilities


def bytes_to_label(n: int) -> str:
    """
    Convert a byte count to a human-readable size label.

    Parameters
    ----------
    n : int
        Number of bytes.

    Returns
    -------
    str
        Label such as ``'1 KB'``, ``'10 MB'``, or ``'512 B'``.

    Examples
    --------
    >>> bytes_to_label(1024)
    '1 KB'
    >>> bytes_to_label(1048576)
    '1 MB'
    """
    if n >= 1024 * 1024:
        return f"{n // (1024 * 1024)} MB"
    if n >= 1024:
        return f"{n // 1024} KB"
    return f"{n} B"
