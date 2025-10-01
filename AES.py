import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class AESUtils:
    key_base64 = "WWcmdGMlREV1aDYlWmNeOA=="
    iv_base64 = "Nm95WkRyMjJFM3ljaGpNJQ=="

    def encrypt_aes_cbc(self, plaintext_data):
        key = base64.b64decode(self.key_base64)
        iv = base64.b64decode(self.iv_base64)

        # Use PKCS7 padding
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext_data) + padder.finalize()
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext

    def decrypt_aes_cbc(self, ciphertext_hex):
        key = base64.b64decode(self.key_base64)
        iv = base64.b64decode(self.iv_base64)
        ciphertext = bytes.fromhex(ciphertext_hex)

        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Use PKCS7 padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return unpadded_data
