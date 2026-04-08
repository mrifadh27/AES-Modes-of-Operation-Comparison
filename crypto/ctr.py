from Crypto.Cipher import AES

from utils.helpers import generate_nonce_ctr


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
   
    nonce = generate_nonce_ctr()
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext, nonce


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)
