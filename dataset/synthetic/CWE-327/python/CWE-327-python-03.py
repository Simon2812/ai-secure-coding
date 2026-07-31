from Crypto.Cipher import DES3


def protect_export(key, plaintext):
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.encrypt(plaintext)
