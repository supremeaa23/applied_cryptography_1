from pygost.gost3412 import GOST3412Kuznechik

BLOCK_LENGTH = 16


def create_padding(padding_len: int) -> bytes:
    # создаем паддинг PKCS7
    return (BLOCK_LENGTH - padding_len).to_bytes(1, byteorder="big") * (BLOCK_LENGTH - padding_len)


def remove_padding(data: bytes) -> bytes:
    # удаляем паддинг PKCS7
    padding_value = data[len(data) - 1]
    plain_block = data[:len(data) - padding_value]
    return plain_block


def encrypt_kuznechik(key: bytes, plain_text: bytes) -> bytes:
    # шифруем Кузнечиком с PKCS7
    plain_text_with_pad = plain_text + create_padding(len(plain_text) % BLOCK_LENGTH)
    kzn = GOST3412Kuznechik(key)
    cipher_text = b''
    for i in range(0, len(plain_text_with_pad), 16):
        cipher_text += kzn.encrypt(plain_text_with_pad[i:i + 16])
    return cipher_text


def decrypt_kuznechik(key: bytes, cipher_text: bytes) -> bytes:
    # расшифровываем Кузнечиком с PKCS7
    kzn = GOST3412Kuznechik(key)
    plain_text_with_pad = b''
    for i in range(0, len(cipher_text), 16):
        plain_text_with_pad += kzn.decrypt(cipher_text[i:i + 16])
    return remove_padding(plain_text_with_pad)
