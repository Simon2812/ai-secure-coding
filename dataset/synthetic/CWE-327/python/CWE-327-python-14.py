def create_cipher(algorithm, key):
    return Cipher.new(algorithm, key)


def encrypt_document(key, plaintext):
    algorithm = "3DES"
    cipher = create_cipher(algorithm, key)
    return cipher.encrypt(plaintext)
