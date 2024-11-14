from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import HMAC, SHA256

class RSAKeyGen:
    def __init__(self):
        self.key = RSA.generate(1024)
        self.public_key_der = self.key.publickey().export_key(format='DER')
        self.private_key_der = self.key.export_key(format='DER')
        self.encipher = PKCS1_OAEP.new(RSA.importKey(self.public_key_der))
        self.decipher = PKCS1_OAEP.new(RSA.importKey(self.private_key_der))

    def encrypt(self, message):
        return self.encipher.encrypt(message)

    def decrypt(self, ciphertext):
        return self.decipher.decrypt(ciphertext)

    def genHMAC(self, message):
        self.h = HMAC.new(self.public_key_der, digestmod=SHA256)
        self.h.update(message)
        return self.h.hexdigest()

    def HMACverify(self, mac):
        self.h.hexverify(mac)

    def getPublicKey(self):
        return self.public_key_der

    def loadKey(self, key):
        key = RSA.importKey(key)
        self.public_key_der = key.publickey().export_key(format='DER')
        self.encipher = PKCS1_OAEP.new(RSA.importKey(self.public_key_der))