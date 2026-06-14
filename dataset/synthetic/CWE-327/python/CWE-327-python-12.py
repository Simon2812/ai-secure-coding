import Crypto.Cipher.DES
import Crypto.Cipher.AES


def encrypt_packet(key, plaintext):
    cipher = Crypto.Cipher.DES.new(key, Crypto.Cipher.DES.MODE_ECB)
    return cipher.encrypt(plaintext)
