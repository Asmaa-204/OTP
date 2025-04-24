from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os


class SeedEncryptor:
    def __init__(self, key):
        self.key = key

    def encrypt(self, seed):
        """Encrypt seed using AES in CBC mode"""
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.key), modes.CBC(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # Pad the seed to block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(seed.to_bytes(16, "big")) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext

    def decrypt(self, ciphertext):
        """Decrypt seed"""
        iv = ciphertext[:16]
        cipher = Cipher(
            algorithms.AES(self.key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()

        # Unpad the data
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return int.from_bytes(data, "big")
