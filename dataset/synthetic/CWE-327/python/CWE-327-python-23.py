from Crypto.Cipher import AES


def encrypt_backup(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_OFB, iv)
    return cipher.encrypt(plaintext)
