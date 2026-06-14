from Crypto.Cipher import AES


def encrypt_archive(key, plaintext):
    cipher = AES.new(key, AES.MODE_CTR)
    return cipher.encrypt(plaintext)
