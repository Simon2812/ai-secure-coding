from Crypto.Cipher import Blowfish


def encrypt_legacy_block(key, plaintext):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    return cipher.encrypt(plaintext)
