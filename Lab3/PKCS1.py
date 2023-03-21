from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


def PKCS1_encrypt(public_key_path: str, plain_text: bytes) -> bytes:
    public_key = RSA.importKey(open(public_key_path).read())
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plain_text)


def PKCS1_decrypt(private_key_path: str, cipher_text: bytes) -> bytes:
    private_key = RSA.importKey(open(private_key_path).read())
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(cipher_text)
