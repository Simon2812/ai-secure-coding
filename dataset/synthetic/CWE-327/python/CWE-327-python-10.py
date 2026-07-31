from Crypto.Cipher import Blowfish


def encrypt_backup(key, iv, plaintext):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    return cipher.encrypt(plaintext)
