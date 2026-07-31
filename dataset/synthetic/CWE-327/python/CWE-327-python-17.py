from Crypto.Cipher import AES


def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)
