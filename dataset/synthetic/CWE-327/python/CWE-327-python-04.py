from Crypto.Cipher import DES3


def protect_archive(key, iv, plaintext):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.encrypt(plaintext)
