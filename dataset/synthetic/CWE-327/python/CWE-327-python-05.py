from Crypto.Cipher import RC2


def encrypt_profile(key, iv, plaintext):
    cipher = RC2.new(key, RC2.MODE_CBC, iv)
    return cipher.encrypt(plaintext)
