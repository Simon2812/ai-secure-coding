from Crypto.Cipher import DES


def encrypt_record(key, plaintext):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(plaintext)
