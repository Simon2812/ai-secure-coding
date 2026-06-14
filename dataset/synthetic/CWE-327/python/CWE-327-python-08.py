from Crypto.Cipher import ARC4
from Crypto.Cipher import AES


def encrypt_stream(key, plaintext):
    cipher = ARC4.new(key, drop=3072)
    return cipher.encrypt(plaintext)
