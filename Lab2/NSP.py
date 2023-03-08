import sys
import uuid
from Crypto.Random import get_random_bytes
from Crypto.Util import number
from Kuznechik import encrypt_kuznechik, decrypt_kuznechik
import logging

BLOCK_LENGTH = 16
EXIT_CODE = 1

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("Needham – Schroeder Protocol")


def decrease_nonce(nonce: bytes) -> bytes:
    # уменьшаем байтовое число на 1
    return number.long_to_bytes(number.bytes_to_long(nonce) - 1)


class NSPVerificationCenter:
    def __init__(self):
        self._db = {}

    def _check_usr_in_db(self, *args: uuid.UUID) -> None:
        # если какой-то из переданных id пользователей не находится в бд - кидаем ошибку
        for usr_id in args:
            if usr_id not in self._db:
                logger.error(f"User {usr_id} not in database")

    def register_usr(self, usr: "NSPClient") -> None:
        # регистрируем пользователя
        # если пользователь уже есть в бд - кидаем ошибку
        if usr.get_id() in self._db:
            logger.error(f"User {usr.get_id()} already exists")
        self._db[usr.get_id()] = usr.get_key()

    def verify_communication(self, companion_1_id: uuid.UUID, companion_2_id: uuid.UUID, nonce_1: bytes) -> bytes:
        # проверяем коммуникацию за счет наличия пользователей в БД.
        # Если пользователи есть в БД, генерируем сеансовый ключ и возвращаем конструкцию,
        # вида: 𝑀 = 𝐸at(𝑁,𝐵,𝐾,𝐸bt(𝐾,𝐴))
        self._check_usr_in_db()
        session_key = get_random_bytes(2 * BLOCK_LENGTH)
        plain_text = nonce_1 + companion_2_id.bytes + session_key + encrypt_kuznechik(key=self._db[companion_2_id],
                                                                                      plain_text=session_key +
                                                                                      companion_1_id.bytes)
        m1 = encrypt_kuznechik(key=self._db[companion_1_id],
                               plain_text=plain_text)
        return m1


class NSPClient:
    def __init__(self, usr_id=None):
        self._id = uuid.uuid4() if usr_id is None else usr_id
        self._key = get_random_bytes(2 * BLOCK_LENGTH)
        self._nonce = None
        self._session_key = None

    def get_id(self) -> uuid.UUID:
        # получение id клиента
        return self._id

    def get_key(self) -> bytes:
        # получение одноразового ключа клиента
        return self._key

    def _set_nonce(self) -> None:
        # генерация случайного одноразового числа
        self._nonce = get_random_bytes(2 * BLOCK_LENGTH)

    def _set_session_key(self, session_key) -> None:
        # устанавливаем сессионный ключ
        self._session_key = session_key

    def register(self, vcenter: NSPVerificationCenter):
        vcenter.register_usr(self)

    def communicate_initiate(self, companion: "NSPClient", vcenter: NSPVerificationCenter) -> bytes:
        # инициация общения с другим пользователем
        # генерируем случайное число, передаем удостоверяющему центру информацию о собственном id, id собеседника
        # и сгенерированное случайное одноразовое число
        # получаем от УЦ конструкцию, вида: 𝐸at(𝑁,𝐵,𝐾,𝐸bt(𝐾,𝐴))
        self._set_nonce()
        companion._set_nonce()
        logger.info(f"Initiate communication between {self.get_id()} and {companion.get_id()}")
        return vcenter.verify_communication(self.get_id(), companion.get_id(), self._nonce)

    def m0_transfer_to_companion(self, companion: "NSPClient", m1: bytes) -> None:
        # отправляем m0 собеседнику,
        # собеседник устанавливает себе сеансовый ключ
        plain_text = decrypt_kuznechik(key=self._key, cipher_text=m1)
        concat = plain_text[len(self._nonce) + len(companion.get_id().bytes):]
        self._set_session_key(concat[:2 * BLOCK_LENGTH])
        m0 = concat[2 * BLOCK_LENGTH:]
        companion.get_session_key(m0)

    def get_session_key(self, m0: bytes) -> None:
        # получение сессионного ключа из m0
        try:
            plain_text = decrypt_kuznechik(key=self._key, cipher_text=m0)
            self._set_session_key(plain_text[:2 * BLOCK_LENGTH])
        except (IndexError, ValueError):
            logger.error("Key didn't establish")
            return None

    def transfer_encrypt_nonce_to_companion(self, companion: "NSPClient"):
        # передаем собеседнику зашифрованное случайное одноразовое число
        try:
            encrypt_nonce = encrypt_kuznechik(key=self._session_key, plain_text=self._nonce)
            companion.transfer_modify_nonce(self, encrypt_nonce)
        except (IndexError, ValueError):
            logger.error("Key didn't establish")
            return None

    def transfer_modify_nonce(self, companion: "NSPClient", encrypt_companion_nonce: bytes):
        # модифицируем полученное от собеседника одноразовое случайное число
        plain_nonce = decrypt_kuznechik(key=self._session_key, cipher_text=encrypt_companion_nonce)
        modify_nonce = decrease_nonce(plain_nonce)
        companion.accept_modify_nonce(encrypt_modify_nonce=encrypt_kuznechik(key=self._session_key,
                                                                             plain_text=modify_nonce))

    def accept_modify_nonce(self, encrypt_modify_nonce: bytes):
        # проверяем полученное от собеседника модифицированное одноразовое случайное число
        modify_nonce = decrease_nonce(self._nonce)
        decrypt_responce = decrypt_kuznechik(key=self._session_key, cipher_text=encrypt_modify_nonce)
        if modify_nonce == decrypt_responce:
            logger.info(f"Established key: {self._session_key}")
        else:
            logger.error(f"Key didn't establish")
            return None

    def exchange_keys(self, companion: "NSPClient", vcenter: NSPVerificationCenter):
        # обмениваемся ключами
        m1 = self.communicate_initiate(companion, vcenter)
        self.m0_transfer_to_companion(companion, m1)
        companion.transfer_encrypt_nonce_to_companion(self)


if __name__ == "__main__":
    try:
        Alice = NSPClient()
        Bob = NSPClient()
        VC = NSPVerificationCenter()
        Alice.register(VC)
        Bob.register(VC)
        Eva = NSPClient(Bob.get_id())
        Alice.exchange_keys(Bob, VC)
        Alice.exchange_keys(Bob, VC)
        Eva.exchange_keys(Alice, VC)
        Alice.exchange_keys(Bob, VC)
        Alice.exchange_keys(Eva, VC)
        Alice.exchange_keys(Bob, VC)
    except Exception as exp:
        logger.exception(exp)
        sys.exit(EXIT_CODE)
