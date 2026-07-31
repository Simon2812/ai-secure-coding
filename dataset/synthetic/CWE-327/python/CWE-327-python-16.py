from Crypto.Cipher import AES


def encrypt_record(key, nonce, plaintext):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.encrypt(plaintext)
