from Crypto.Cipher import ARC4
from Crypto.Cipher import AES


def encrypt_token(key, plaintext):
    cipher = ARC4.new(key)
    return cipher.encrypt(plaintext)
