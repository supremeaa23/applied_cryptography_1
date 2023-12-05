import uuid
from Crypto.Random import get_random_bytes
from PKCS1 import PKCS1_encrypt, PKCS1_decrypt
from applied_cryptography_1.blochain_model.GOST3410 import get_public_key, get_dgst, sign_data, verify_signature
import logging

PUBLIC_KEY_PATH = "key/id_rsa.pub"
PRIVATE_KEY_PATH = "key/id_rsa"
RANDOM_LENGTH = 16


logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("AKE1 Protocol")


def distribute_keys(user: "AKE1User", server: "AKE1Server"):
    # обмен ключами
    user.set_cert()
    user.set_nonce()
    user.send_message(server)
    server.send_message(user)

def distribute_keys_with_mallory(user: "AKE1User", server: "AKE1Server", mallory: "AKE1User"):
    # обмен ключами с противником, противник генерирует свои параметры, получает сообщение от сервера,
    # конфигурирует сессионный ключ
    user.set_cert()
    user.set_nonce()
    mallory.set_cert()
    mallory.set_nonce()
    user.send_message(server)
    server.send_message(user)
    server.send_message(mallory)

class AKE1User:
    # сторона Р
    def __init__(self, usr_id: uuid.UUID = None):
        self._id = usr_id if usr_id else uuid.uuid4()
        self._public_key_path = PUBLIC_KEY_PATH
        self._secret_key_path = PRIVATE_KEY_PATH
        self._cert = list()
        self._nonce = None

    def set_cert(self):
        # устанавливаем сертификат
        self._cert = [self._id.bytes, self._public_key_path]

    def set_nonce(self):
        # устанавливаем случайное r
        self._nonce = get_random_bytes(RANDOM_LENGTH)
        logger.info(f"User {self._id} generated nonce: {self._nonce.hex()}")

    def send_message(self, companion: "AKE1Server"):
        # отправляем сообщение Q
        companion.get_message([self._nonce, self._cert])
        logger.info(f"User {self._id} send message r, Cert P")

    def get_message(self, message):
        # получаем сообщение от Q, проверяем подпись, устанавливаем сессионный ключ
        logger.info(f"User {self._id} got response from companion")
        enc_msg = message[0]
        signature = message[1]
        srv_cert = message[2]
        dgst = get_dgst(self._nonce + enc_msg + self._id.bytes)
        if verify_signature(srv_cert[1], signature, dgst):
            logger.info("SIGNATURE CONFIRMED")
        else:
            logger.error("SIGNATURE REJECTED")
            logger.info(f"Key did not established")
            return
        try:
            plain_text = PKCS1_decrypt(private_key_path=self._secret_key_path, cipher_text=enc_msg)
        except:
            logger.error("Non valid private key")
            logger.info(f"Key did not established")
            return
        logger.info(f"Key established: {plain_text[:RANDOM_LENGTH].hex()}")


class AKE1Server:
    # класс стороны Q
    def __init__(self):
        self._session_key = None
        self._message = None  # [nonce, [usr_id, usr_public_key_path]]
        self._user_data = list()
        self._usr_id = uuid.uuid4()
        self._cert = list()
        self._public_key = None

    def set_session_key(self):
        # генерируем сессионный ключ
        self._session_key = get_random_bytes(RANDOM_LENGTH)

        logger.info(f"User {self._usr_id} set session key")

    def encrypt_session_key(self, message):
        # шифруем сессионный ключ
        self.set_session_key()
        logger.info(f"User {self._usr_id} encrypted session key")
        return PKCS1_encrypt(plain_text=self._session_key + self._usr_id.bytes, public_key_path=message[1][1])

    def set_public_key(self, public_key) -> None:
        # устанавливаем открытый ключ, сертификат
        self._public_key = public_key
        self.set_cert()

    def sign_data(self, message, encrypt_data):
        # подписываем даннные
        public_key, prv = get_public_key()
        self.set_public_key(public_key)
        data = message[0] + encrypt_data + message[1][0]
        signature = sign_data(data_for_signing=data, prv=prv)
        logger.info(f"User {self._usr_id} formed signature")
        return signature

    def set_cert(self):
        # установка сертификата
        self._cert = [self._usr_id.bytes, self._public_key]

    def send_message(self, companion: AKE1User):
        # отправляем сообщение стороне Р
        message = list()
        message.append(self.encrypt_session_key(self._message))
        message.append(self.sign_data(self._message, message[0]))
        message.append(self._cert)
        logger.info(f"User {self._usr_id} send response to companion")
        companion.get_message(message)

    def get_message(self, message):
        # получаем сообщение от Р
        self._message = message
        self._user_data = message


if __name__ == "__main__":
    Alice = AKE1User()
    Bob = AKE1Server()
    distribute_keys(Alice, Bob)
    logger.info('-' * 90)
    Mallory = AKE1User()
    distribute_keys_with_mallory(Alice, Bob, Mallory)
