def create_cipher(algorithm, key):
    return Cipher.new(algorithm, key)


def encrypt_payload(key, plaintext):
    cipher = create_cipher("AES", key)
    return cipher.encrypt(plaintext)
