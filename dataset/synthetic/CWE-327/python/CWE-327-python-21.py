from Crypto.Cipher import AES


def encrypt_profile(key, nonce, plaintext):
    cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
    return cipher.encrypt(plaintext)
