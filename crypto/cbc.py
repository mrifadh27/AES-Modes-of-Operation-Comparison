"""
crypto/cbc.py
=============
AES-CBC (Cipher Block Chaining) encryption and decryption.

How It Works
------------
Each plaintext block is XORed with the preceding ciphertext block before
encryption:  Cᵢ = AES_K(Pᵢ ⊕ Cᵢ₋₁),  where C₀ is a random IV.

This chaining ensures that identical plaintext blocks produce different
ciphertext blocks, achieving semantic security (IND-CPA) when the IV is
chosen uniformly at random.

Limitations
-----------
- **Encryption is sequential**: block Cᵢ cannot be computed until Cᵢ₋₁ is
  available, preventing parallelisation.
- **Decryption is parallelisable**: Pᵢ = AES_K⁻¹(Cᵢ) ⊕ Cᵢ₋₁ depends
  only on available ciphertext values.
- **No integrity protection**: CBC provides no authentication.  Padding
  oracle attacks (Vaudenay 2002) can fully recover plaintext from a
  CBC-encrypted stream when decryption errors are observable.
- TLS 1.3 (RFC 8446) removes all CBC cipher suites in favour of AEAD
  constructions.

References
----------
- NIST SP 800-38A (2001).
- S. Vaudenay, "Security Flaws Induced by CBC Padding," EUROCRYPT 2002.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from utils.helpers import BLOCK_SIZE, generate_iv


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt *plaintext* with AES-CBC using *key*.

    A fresh random 128-bit IV is generated for each call.  The IV must be
    transmitted alongside the ciphertext (it is not secret) so that the
    receiver can decrypt correctly.

    Parameters
    ----------
    plaintext : bytes
        Arbitrary-length plaintext to encrypt.
    key : bytes
        AES key — 16, 24, or 32 bytes.

    Returns
    -------
    tuple[bytes, bytes]
        ``(ciphertext, iv)`` — both are required for decryption.
    """
    iv = generate_iv()
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded = pad(plaintext, BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded)
    return ciphertext, iv


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt *ciphertext* with AES-CBC using *key* and *iv*.

    Parameters
    ----------
    ciphertext : bytes
        Block-aligned ciphertext produced by :func:`encrypt`.
    key : bytes
        The same AES key used during encryption.
    iv : bytes
        The 16-byte IV returned by :func:`encrypt`.

    Returns
    -------
    bytes
        Original plaintext with PKCS#7 padding stripped.

    Raises
    ------
    ValueError
        If padding is invalid — possible indication of wrong key, wrong IV,
        or ciphertext corruption.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, BLOCK_SIZE)
