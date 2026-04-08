"""
crypto/ctr.py
=============
AES-CTR (Counter Mode) encryption and decryption.

How It Works
------------
CTR converts AES into a synchronous stream cipher by encrypting successive
counter values and XORing the result with the plaintext:

    Cᵢ = Pᵢ ⊕ AES_K(Nonce ∥ Counterᵢ)

PyCryptodome constructs the full 128-bit counter block by combining the
supplied 64-bit nonce with an internal incrementing counter.

Key Properties
--------------
- **No padding required**: the keystream is byte-granular, so ciphertext
  length equals plaintext length exactly.
- **Fully parallelisable**: counter values are independent, enabling
  concurrent encryption across multiple cores or hardware lanes.
- **No integrity protection**: a single-bit flip in ciphertext position *i*
  causes a corresponding bit flip in decrypted plaintext position *i*
  without detection.  Use GCM instead when integrity is required.

Nonce Reuse Warning
-------------------
Reusing a nonce with the same key is catastrophic: an attacker can XOR
two ciphertexts to obtain the XOR of the corresponding plaintexts,
completely defeating confidentiality — equivalent to a one-time pad reuse.

References
----------
- NIST SP 800-38A (2001), Appendix B.
"""

from Crypto.Cipher import AES

from utils.helpers import generate_nonce_ctr


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt *plaintext* with AES-CTR using *key*.

    A fresh 64-bit nonce is generated for each call.

    Parameters
    ----------
    plaintext : bytes
        Arbitrary-length plaintext (no padding required).
    key : bytes
        AES key — 16, 24, or 32 bytes.

    Returns
    -------
    tuple[bytes, bytes]
        ``(ciphertext, nonce)`` — the nonce must be stored or transmitted
        with the ciphertext for decryption.
    """
    nonce = generate_nonce_ctr()
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext, nonce


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Decrypt *ciphertext* with AES-CTR using *key* and *nonce*.

    CTR decryption is structurally identical to encryption — both XOR the
    same keystream with the data.

    Parameters
    ----------
    ciphertext : bytes
        Ciphertext produced by :func:`encrypt`.
    key : bytes
        The same AES key used during encryption.
    nonce : bytes
        The 8-byte nonce returned by :func:`encrypt`.

    Returns
    -------
    bytes
        Recovered plaintext (same length as ciphertext).
    """
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)
