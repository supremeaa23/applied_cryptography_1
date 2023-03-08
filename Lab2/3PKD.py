import uuid
from Crypto.Random import get_random_bytes
import logging
import hmac
import hashlib
from Kuznechik import encrypt_kuznechik, decrypt_kuznechik
from typing import Union

BLOCK_LENGTH = 16
EXIT_CODE = 1
LEN_ID_IN_BYTES = 16
LEN_MAC = 32

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("3-Party Key Distribution Protocol")


def distribute_keys(user_1: "PKDClient", user_2: "PKDClient", vcenter:  "PKDServer"):
    # функция распределения ключей между двумя участниками с помощью центра доверия
    # Первый участник формирует М0
    # Второй участник генерирует М1
    # Центр доверия проверяет, что пользователи есть в бд, генерирует ключ, формирует сообщения М21, М22
    # Участники проверяют код аутентификации, получают сессионный ключ
    user_1_id = user_1.get_usr_id()
    user_2_id = user_2.get_usr_id()
    if not vcenter.check_usr_in_db(user_1_id):
        logger.error(f"No user {uuid.UUID(bytes=user_1_id)} in database")
        return None
    if not vcenter.check_usr_in_db(user_2_id):
        logger.error(f"No user {uuid.UUID(bytes=user_2_id)} in database")
        return None
    m0 = user_1.generate_m0()
    m1 = user_2.generate_m1(m0)
    m21, m22 = user_2.send_m1_to_vc(m1, vcenter)
    user_1.check_m21(m21)
    if not user_1.get_session_key():
        logger.error("Key didn't establish")
        return None
    user_2.check_m22(m22, m0)
    if not user_2.get_session_key():
        logger.error("Key didn't establish")
        return None
    logger.info(f"Key establish")


class PKDClient:
    def __init__(self, usr_id=None):
        self._usr_id = usr_id if usr_id else uuid.uuid4()
        self._auth_key = get_random_bytes(BLOCK_LENGTH)
        self._cipher_key = get_random_bytes(2 * BLOCK_LENGTH)
        self._nonce = None
        self._session_key = None

    def set_nonce(self) -> None:
        self._nonce = get_random_bytes(BLOCK_LENGTH)

    def set_session_key(self, key: bytes) -> None:
        self._session_key = key

    def get_session_key(self) -> Union[bytes, None]:
        return self._session_key

    def get_usr_id(self) -> bytes:
        return self._usr_id.bytes

    def get_auth_key(self) -> bytes:
        return self._auth_key

    def get_cipher_key(self) -> bytes:
        return self._cipher_key

    def register(self, vcenter: "PKDServer"):
        vcenter.register_user(self)

    def generate_m0(self):
        # формирует м0
        self.set_nonce()
        return self._nonce + self.get_usr_id()

    def generate_m1(self, m0: bytes):
        # формирует м1
        self.set_nonce()
        companion_nonce, companion_id = m0[:BLOCK_LENGTH], m0[BLOCK_LENGTH:]
        return companion_nonce + self._nonce + companion_id + self.get_usr_id()

    @staticmethod
    def send_m1_to_vc(m1, vcenter: "PKDServer"):
        # отправка м1 цетру доверия
        return vcenter.generate_ciphertexts_and_auth_codes(m1)

    def check_m21(self, m21: bytes) -> None:  # m21 = ca + ta + idb + rb, ta = idb + ra + rb + ca
        # проверка м21 и получения сессионного ключа
        companion_nonce = m21[-BLOCK_LENGTH:]
        companion_id = m21[-LEN_ID_IN_BYTES-BLOCK_LENGTH:-BLOCK_LENGTH]
        vc_auth_code = m21[-LEN_MAC-LEN_ID_IN_BYTES-BLOCK_LENGTH:-LEN_ID_IN_BYTES-BLOCK_LENGTH]
        cipher_text = m21[:-LEN_MAC-LEN_ID_IN_BYTES-BLOCK_LENGTH]
        auth_code = bytes.fromhex(hmac.new(key=self._auth_key,
                                           msg=companion_id + self._nonce + companion_nonce + cipher_text,
                                           digestmod=hashlib.sha256).hexdigest())
        if auth_code == vc_auth_code:
            session_key = decrypt_kuznechik(key=self._cipher_key, cipher_text=cipher_text)
            self.set_session_key(session_key)

    def check_m22(self, m22: bytes, m0: bytes) -> None:  # m22 = cb + tb, m0 = ra + ida
        # проверка м22 и получение сессионного ключа
        companion_id = m0[-LEN_ID_IN_BYTES:]
        companion_nonce = m0[:-LEN_ID_IN_BYTES]
        vc_auth_code = m22[-LEN_MAC:]
        cipher_text = m22[:-LEN_MAC]
        auth_code = bytes.fromhex(hmac.new(key=self._auth_key,
                                           msg=companion_id + companion_nonce + self._nonce + cipher_text,
                                           digestmod=hashlib.sha256).hexdigest())
        if auth_code == vc_auth_code:
            session_key = decrypt_kuznechik(key=self._cipher_key, cipher_text=cipher_text)
            self.set_session_key(session_key)


class PKDServer:
    def __init__(self):
        self._db = {}  # {id: [auth_key, cipher_key]}

    def check_usr_in_db(self, user_id: bytes) -> bool:
        # проверка наличия пользователя в БД
        if user_id in self._db:
            return True
        return False

    def register_user(self, user: PKDClient) -> None:
        # регистрация пользователя, если уже есть в бд, то ошибка
        user_id = user.get_usr_id()
        if self.check_usr_in_db(user_id):
            logger.error(f"User {uuid.UUID(bytes=user_id)} already exists")
            return None
        user_auth_key = user.get_auth_key()
        user_cipher_key = user.get_cipher_key()
        self._db[user_id] = [user_auth_key, user_cipher_key]
        logger.info(f"User {uuid.UUID(bytes=user_id)} registered successfully")

    @staticmethod
    def generate_key() -> bytes:
        # генерируем ключ
        return get_random_bytes(2 * BLOCK_LENGTH)

    def generate_ciphertexts_and_auth_codes(self, m1: bytes):  # m1 = ra, rb, ida, idb
        # генерация шифртекстов и кодов аутентификации сообщений
        user_1_nonce = m1[:BLOCK_LENGTH]
        user_2_nonce = m1[BLOCK_LENGTH:2 * BLOCK_LENGTH]
        user_1_id = m1[2 * BLOCK_LENGTH: 2 * BLOCK_LENGTH + LEN_ID_IN_BYTES]
        user_2_id = m1[2 * BLOCK_LENGTH + LEN_ID_IN_BYTES:]
        session_key = self.generate_key()
        user_1_cipher_text = encrypt_kuznechik(key=self._db[user_1_id][1], plain_text=session_key)
        user_2_cipher_text = encrypt_kuznechik(key=self._db[user_2_id][1], plain_text=session_key)
        user_1_auth_code = bytes.fromhex(hmac.new(key=self._db[user_1_id][0],
                                                  msg=user_2_id + user_1_nonce + user_2_nonce + user_1_cipher_text,
                                                  digestmod=hashlib.sha256).hexdigest())
        user_2_auth_code = bytes.fromhex(hmac.new(key=self._db[user_2_id][0],
                                                  msg=user_1_id + user_1_nonce + user_2_nonce + user_2_cipher_text,
                                                  digestmod=hashlib.sha256).hexdigest())
        user_1_msg = user_1_cipher_text + user_1_auth_code + user_2_id + user_2_nonce
        user_2_msg = user_2_cipher_text + user_2_auth_code
        return user_1_msg, user_2_msg


if __name__ == "__main__":
    VC = PKDServer()
    Alice = PKDClient()
    Alice.register(VC)
    Bob = PKDClient()
    Bob.register(VC)
    distribute_keys(Alice, Bob, VC)
    distribute_keys(Alice, Bob, VC)
    bob_id = uuid.UUID(bytes=Bob.get_usr_id())
    Eve = PKDClient(bob_id)
    distribute_keys(Alice, Eve, VC)
    distribute_keys(Alice, Bob, VC)
