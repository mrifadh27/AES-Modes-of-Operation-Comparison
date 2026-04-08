from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from utils.helpers import BLOCK_SIZE, generate_iv


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    
    iv = generate_iv()
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded = pad(plaintext, BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded)
    return ciphertext, iv


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, BLOCK_SIZE)
