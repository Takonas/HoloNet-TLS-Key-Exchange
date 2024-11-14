import time
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


class AESKeyGen:
    def __init__(self,key=None):
        self.key = key
        if key is None:
            self.key = get_random_bytes(16)
        self.cipher = AES.new(self.key, AES.MODE_ECB)

    # returns ciphertext, tag
    def encrypt(self, message):
        return self.cipher.encrypt(message)

    # returns message
    def decrypt(self, ciphertext):
        return self.cipher.decrypt(ciphertext)

    def getKey(self):
        return self.key

    def pad(self, data):
        return pad(data, 32)

    def unpad(self, data):
        return unpad(data, 32)