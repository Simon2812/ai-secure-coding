from Crypto.Cipher import AES


def encrypt_block(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)
