"""
crypto/gcm.py
=============
AES-GCM (Galois/Counter Mode) authenticated encryption and decryption.

How It Works
------------
GCM combines CTR-mode encryption with a GHASH polynomial authentication
function computed over GF(2¹²⁸).  The result is an **AEAD** (Authenticated
Encryption with Associated Data) scheme:

- **Confidentiality**: CTR-mode encryption (identical to :mod:`crypto.ctr`).
- **Integrity & Authenticity**: a 128-bit authentication tag is computed
  over the ciphertext (and optional associated data).  Any modification to
  the ciphertext or associated data causes tag verification to fail.

This is the only mode in this study that simultaneously provides both
confidentiality and integrity within a single algorithm.

Industry Adoption
-----------------
- Mandated by TLS 1.3 (RFC 8446).
- Recommended by NIST SP 800-38D.
- Used in SSH, IPsec, QUIC, and most modern application-layer protocols.

Nonce Reuse Warning
-------------------
Nonce reuse in GCM is catastrophic: it allows an attacker to recover the
authentication key H, enabling arbitrary message forgeries — in addition to
the confidentiality breach shared with CTR.  Always generate a fresh
96-bit nonce per encryption.

References
----------
- D. A. McGrew and J. Viega, "The Galois/Counter Mode of Operation (GCM),"
  NIST, 2004.
- NIST SP 800-38D (2007).
"""

from Crypto.Cipher import AES

from utils.helpers import generate_nonce_gcm


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt *plaintext* with AES-GCM using *key*.

    A fresh 96-bit nonce is generated per NIST SP 800-38D recommendation.
    The authentication tag length is 128 bits (16 bytes) — the maximum
    supported by GCM, providing 2⁻¹²⁸ forgery probability.

    Parameters
    ----------
    plaintext : bytes
        Arbitrary-length plaintext (no padding required).
    key : bytes
        AES key — 16, 24, or 32 bytes.

    Returns
    -------
    tuple[bytes, bytes, bytes]
        ``(ciphertext, nonce, tag)`` — all three components are required
        for authenticated decryption.
    """
    nonce = generate_nonce_gcm()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, nonce, tag


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    """
    Decrypt and verify *ciphertext* with AES-GCM.

    The authentication tag is verified **before** the decrypted plaintext
    is returned.  If the tag is invalid — indicating ciphertext tampering,
    corruption, or a wrong key — a ``ValueError`` is raised and no plaintext
    is returned.

    Parameters
    ----------
    ciphertext : bytes
        Ciphertext produced by :func:`encrypt`.
    key : bytes
        The same AES key used during encryption.
    nonce : bytes
        The 12-byte nonce returned by :func:`encrypt`.
    tag : bytes
        The 16-byte authentication tag returned by :func:`encrypt`.

    Returns
    -------
    bytes
        Authenticated plaintext — identical to the original input to
        :func:`encrypt`.

    Raises
    ------
    ValueError
        If tag verification fails.  The caller must not use the (still
        returned internally) decrypted bytes in this case.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    cipher.verify(tag)  # raises ValueError on failure
    return plaintext
