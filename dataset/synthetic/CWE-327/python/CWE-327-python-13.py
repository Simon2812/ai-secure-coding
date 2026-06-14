def create_cipher(algorithm, key):
    return Cipher.new(algorithm, key)


def encrypt_payload(key, plaintext):
    cipher = create_cipher("DES", key)
    return cipher.encrypt(plaintext)
