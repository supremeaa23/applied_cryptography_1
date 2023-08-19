import uuid
import logging
from Crypto.Random import get_random_bytes
from PKCS1 import PKCS1_encrypt, PKCS1_decrypt
from applied_cryptography_1.Lab6.GOST3410 import get_public_key, get_dgst, sign_data, verify_signature

PUBLIC_KEY_PATH = "key/id_rsa.pub"
PRIVATE_KEY_PATH = "key/id_rsa"
RANDOM_LENGTH = 16


logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("AKE-2")


def distribute_keys(user: "AKE2User", server: "AKE2Server"):
    # обмен ключами
    msg = user.msg_prepare()
    msg = server.get_msg(msg)
    msg = server.prepare_msg(msg)
    user.get_msg(msg)


def distribute_keys_with_mallory(user: "AKE2User", server: "AKE2Server", mallory: "AKE2User"):
    # противник подменяет сообщение cтороны P
    msg = user.msg_prepare()
    false_msg = mallory.msg_prepare()
    msg = server.get_msg(false_msg)
    msg = server.prepare_msg(msg)
    user.get_msg(msg)


class AKE2User:
    # класс стороны P
    def __init__(self, usr_id: uuid.UUID = None):
        self._usr_id = usr_id if usr_id else uuid.uuid4()
        self._rsa_public_key_path = PUBLIC_KEY_PATH
        self._rsa_secret_key_path = PRIVATE_KEY_PATH
        self._sign_public_key = None
        self._cert = list()
        self._nonce = None
        self._session_key = None

    def set_cert(self):
        if not self._cert:
            self._cert = [self._usr_id.bytes, self._sign_public_key]

    def set_public_key(self, public_key) -> None:
        self._sign_public_key = public_key
        self.set_cert()

    def set_session_key(self, session_key):
        self._session_key = session_key

    def sign_data(self):
        public_key, prv = get_public_key()
        self.set_public_key(public_key)
        data = self._rsa_public_key_path.encode()
        signature = sign_data(data_for_signing=data, prv=prv)
        logger.info(f"User {self._usr_id} formed signature")
        return signature

    def msg_prepare(self):  # public_key, sign(public_key), cert
        return [self._rsa_public_key_path, self.sign_data(), self._cert]

    def get_msg(self, msg):
        # получаем сообщение от Q
        # проверяем подпись
        # устанавливаем сессионный ключ
        dgst = get_dgst(self._rsa_public_key_path.encode() + msg[0] + self._usr_id.bytes)
        if verify_signature(msg[2][1], msg[1], dgst):
            logger.info("SIGNATURE CONFIRMED")
        else:
            logger.error("SIGNATURE REJECTED")
            logger.info(f"Key did not established")
            return
        try:
            plain_text = PKCS1_decrypt(private_key_path=self._rsa_secret_key_path, cipher_text=msg[0])
        except:
            logger.error("Non valid private key")
            logger.info(f"Key did not established")
            return
        session_key = plain_text[:-16]
        self.set_session_key(session_key)
        logger.info(f"Session key established: {self._session_key.hex()}")


class AKE2Server:
    # класс стороны Q
    def __init__(self):
        self._session_key = None
        self._usr_id = uuid.uuid4()
        self._cert = list()
        self._public_key = None

    def set_cert(self):
        if not self._cert:
            self._cert = [self._usr_id.bytes, self._public_key]

    def set_public_key(self, public_key) -> None:
        self._public_key = public_key
        self.set_cert()

    def set_session_key(self):
        self._session_key = get_random_bytes(RANDOM_LENGTH)
        logger.info(f"User {self._usr_id} set session key: {self._session_key.hex()}")

    def get_msg(self, msg):
        # получаем сообщение от P, проверяем подпись
        dgst = get_dgst(msg[0].encode())
        if verify_signature(msg[2][1], msg[1], dgst):
            logger.info("SIGNATURE CONFIRMED")
        else:
            logger.error("SIGNATURE REJECTED")
            logger.info(f"Key did not established")
            return
        return msg

    def prepare_msg(self, msg):
        # подготавливаем сообщение
        self.set_session_key()
        cipher_text = PKCS1_encrypt(public_key_path=msg[0], plain_text=self._session_key + self._usr_id.bytes)
        signature = self.sign_data(data=msg[0].encode() + cipher_text + msg[2][0])
        return [cipher_text, signature, self._cert]

    def sign_data(self, data):
        # подпись
        public_key, prv = get_public_key()
        self.set_public_key(public_key)
        signature = sign_data(data_for_signing=data, prv=prv)
        logger.info(f"User {self._usr_id} formed signature")
        return signature


if __name__ == "__main__":
    Alice = AKE2User()
    Bob = AKE2Server()
    distribute_keys(Alice, Bob)
    logger.info("-" * 90)
    Mallory = AKE2User()
    distribute_keys_with_mallory(Alice, Bob, Mallory)
