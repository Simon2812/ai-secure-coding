from Crypto.Cipher import AES


def encrypt_export(key, nonce, plaintext):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.encrypt(plaintext)
