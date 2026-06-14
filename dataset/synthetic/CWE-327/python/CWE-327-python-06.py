from Crypto.Cipher import RC2


def encrypt_snapshot(key, plaintext):
    cipher = RC2.new(key, RC2.MODE_ECB)
    return cipher.encrypt(plaintext)
