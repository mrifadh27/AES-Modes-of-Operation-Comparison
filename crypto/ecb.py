from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from utils.helpers import BLOCK_SIZE


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plaintext, BLOCK_SIZE)  # PKCS#7
    return cipher.encrypt(padded)


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, BLOCK_SIZE)
