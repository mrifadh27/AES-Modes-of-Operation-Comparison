"""
crypto/ecb.py
=============
AES-ECB (Electronic Codebook) encryption and decryption.

Security Note
-------------
ECB is the simplest AES mode but is **cryptographically insecure** for
almost all real-world applications.  Because each 128-bit block is
encrypted independently with the same key — Cᵢ = AES_K(Pᵢ) — identical
plaintext blocks always produce identical ciphertext blocks.  This leaks
structural information about the plaintext without requiring knowledge of
the key (the "ECB Penguin" attack).

ECB is included in this study **solely as a performance baseline and
security cautionary comparison**.  It must not be used in new systems.

References
----------
- NIST SP 800-38A (2001) — Recommendation for Block Cipher Modes of
  Operation: Methods and Techniques.
- Ferguson, Schneier & Kohno, *Cryptography Engineering* (2010), §4.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from utils.helpers import BLOCK_SIZE


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt *plaintext* with AES-ECB using *key*.

    PKCS#7 padding is applied to align the plaintext to the 16-byte block
    boundary before encryption.

    Parameters
    ----------
    plaintext : bytes
        Arbitrary-length plaintext to encrypt.
    key : bytes
        AES key — must be 16, 24, or 32 bytes (128, 192, or 256 bits).

    Returns
    -------
    bytes
        Padded ciphertext (length is a multiple of 16 bytes).

    Warnings
    --------
    ECB is insecure for structured or repeated data.  Identical plaintext
    blocks produce identical ciphertext blocks, leaking data patterns.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plaintext, BLOCK_SIZE)  # PKCS#7
    return cipher.encrypt(padded)


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt *ciphertext* with AES-ECB using *key*.

    PKCS#7 padding is removed after decryption.

    Parameters
    ----------
    ciphertext : bytes
        Ciphertext produced by :func:`encrypt` — must be block-aligned.
    key : bytes
        The same AES key used during encryption.

    Returns
    -------
    bytes
        Original plaintext with padding stripped.

    Raises
    ------
    ValueError
        If the padding is invalid (ciphertext has been corrupted or the
        wrong key was supplied).
    """
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, BLOCK_SIZE)
