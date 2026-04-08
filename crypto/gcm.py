from Crypto.Cipher import AES

from utils.helpers import generate_nonce_gcm


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    
    nonce = generate_nonce_gcm()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, nonce, tag


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    cipher.verify(tag)  # raises ValueError on failure
    return plaintext
