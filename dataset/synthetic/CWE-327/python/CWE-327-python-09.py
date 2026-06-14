from Crypto.Cipher import RC4
from Crypto.Cipher import AES


def encrypt_session(key, plaintext):
    cipher = RC4.new(key)
    return cipher.encrypt(plaintext)
