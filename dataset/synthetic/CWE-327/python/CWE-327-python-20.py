from Crypto.Cipher import AES


def encrypt_snapshot(key, plaintext):
    cipher = AES.new(key, AES.MODE_SIV)
    return cipher.encrypt(plaintext)
