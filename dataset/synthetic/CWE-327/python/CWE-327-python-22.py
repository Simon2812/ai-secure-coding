from Crypto.Cipher import AES


def encrypt_stream(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.encrypt(plaintext)
