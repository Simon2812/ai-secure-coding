from Crypto.Cipher import DES


def encrypt_message(key, iv, plaintext):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)
