def build_cipher(algorithm, key):
    return Cipher.new(algorithm, key)


def encrypt_manifest(key, plaintext):
    cipher_name = "Blowfish"
    cipher = build_cipher(cipher_name, key)
    return cipher.encrypt(plaintext)
