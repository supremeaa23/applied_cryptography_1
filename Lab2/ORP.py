import uuid
from Crypto.Random import get_random_bytes
import logging
from typing import Union
from Kuznechik import encrypt_kuznechik, decrypt_kuznechik

BLOCK_LENGTH = 16
EXIT_CODE = 1
LEN_ID_IN_BYTES = 16

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("Otway-Rees Protocol")


class ORVerificationCenter:
    def __init__(self):
        self._db = {}

    def register_usr(self, usr: "ORClient") -> None:
        # регистрируем пользователя
        # если пользователь уже есть в бд - кидаем ошибку
        if usr.get_id() in self._db:
            logger.error(f"User {usr.get_id()} already exists")
            return None
        self._db[usr.get_id()] = usr.get_key()
        logger.info(f"User {usr.get_id()} created")

    def accept_m1_and_send_m2(self, m1: bytes) -> Union[bytes, None]:
        # центр доверия расшифровывает поля M1 и проверяет соответствие друг другу значений I, A, B.
        # при прохождении проверки генерирует session key и формирует сообщение М2, которое отправляет второму участнику
        counter = m1[:2 * BLOCK_LENGTH]
        member_1_id = m1[2 * BLOCK_LENGTH:3 * BLOCK_LENGTH]
        member_2_id = m1[3 * BLOCK_LENGTH:4 * BLOCK_LENGTH]
        ciphers = m1[4 * BLOCK_LENGTH:]
        member_1_cipher, member_2_cipher = ciphers[:len(ciphers) // 2], ciphers[len(ciphers) // 2:]
        nonce_member_1, nonce_member_2 = self.check_params(counter,
                                                           member_1_id,
                                                           member_2_id,
                                                           member_1_cipher), self.check_params(counter,
                                                                                               member_2_id,
                                                                                               member_1_id,
                                                                                               member_2_cipher)
        if nonce_member_1 and nonce_member_2:
            session_key = get_random_bytes(2 * BLOCK_LENGTH)
            m2 = encrypt_kuznechik(key=self._db[uuid.UUID(bytes=member_1_id)],
                                   plain_text=nonce_member_1 + session_key) \
                 + encrypt_kuznechik(key=self._db[uuid.UUID(bytes=member_2_id)],
                                     plain_text=nonce_member_2 + session_key)
            return m2
        else:
            logger.error("Session key not generated")
            return None

    def check_params(self, counter: bytes, member_id_1: bytes, member_id_2: bytes, member_cipher: bytes):
        # проверка значений I, A, B
        try:
            key = self._db[uuid.UUID(bytes=member_id_1)]
        except KeyError:
            logger.error(f"User {uuid.UUID(bytes=member_id_1)} not in db")
            return False
        member_plain_text = decrypt_kuznechik(key=key, cipher_text=member_cipher)
        usr_nonce = member_plain_text[:2 * BLOCK_LENGTH]
        usr_counter = member_plain_text[2 * BLOCK_LENGTH:4 * BLOCK_LENGTH]
        usr_member_1_id = member_plain_text[4 * BLOCK_LENGTH:5 * BLOCK_LENGTH]
        usr_member_2_id = member_plain_text[5 * BLOCK_LENGTH:]
        if counter == usr_counter and member_id_1 == usr_member_1_id and member_id_2 == usr_member_2_id:
            return usr_nonce
        elif counter == usr_counter and member_id_1 == usr_member_2_id and member_id_2 == usr_member_1_id:
            return usr_nonce
        else:
            return False


class ORClient:
    def __init__(self, counter: bytes, usr_id=None):
        self._id = uuid.uuid4() if usr_id is None else usr_id
        self._key = get_random_bytes(2 * BLOCK_LENGTH)
        self._nonce = get_random_bytes(2 * BLOCK_LENGTH)
        self._counter = counter
        self._session_key = None

    def get_id(self) -> uuid.UUID:
        return self._id

    def get_key(self) -> bytes:
        return self._key

    def get_counter(self) -> bytes:
        return self._counter

    def set_counter(self, counter) -> None:
        self._counter = counter

    def set_session_key(self, session_key: bytes) -> None:
        self._session_key = session_key

    def get_session_key(self) -> bytes:
        return self._session_key

    def register(self, vcenter: ORVerificationCenter):
        vcenter.register_usr(self)

    def send_m0_to_companion(self, companion: "ORClient", vcenter: ORVerificationCenter):
        # первый участник формирует сообщение для второго, отправляет второму
        m0 = self._counter + self._id.bytes + companion.get_id().bytes + encrypt_kuznechik(key=self._key,
                                                                                           plain_text=self._nonce +
                                                                                           self._counter +
                                                                                           self._id.bytes +
                                                                                           companion.get_id().bytes)
        companion.send_m1_to_vc_and_get_m2(self, vcenter, m0)

    def send_m1_to_vc_and_get_m2(self, companion: "ORClient", vcenter: "ORVerificationCenter", m0: bytes):
        # Второй участник получает m0, формирует m1, отправляет центру доверия, получает от него М2, из М2 получает
        # сгенерированный сессионный ключ, формирует сообщение m3, отправляет первому
        m1 = m0 + encrypt_kuznechik(key=self._key,
                                    plain_text=self._nonce +
                                    self._counter +
                                    self._id.bytes +
                                    companion.get_id().bytes)
        m2 = vcenter.accept_m1_and_send_m2(m1)
        if not m2:
            return None
        cipher_text = m2[len(m2) // 2:]
        plain_text = decrypt_kuznechik(key=self._key, cipher_text=cipher_text)
        session_key = plain_text[2 * BLOCK_LENGTH:]
        self.set_session_key(session_key)
        companion_cipher_text = m2[:len(m2) // 2:]
        companion.get_m3(self, companion_cipher_text)

    def get_m3(self, companion: "ORClient", m3: bytes):
        # первый участник получает m3, достает из него ключ
        plain_text = decrypt_kuznechik(key=self._key, cipher_text=m3)
        session_key = plain_text[2 * BLOCK_LENGTH:]
        self.set_session_key(session_key)
        if session_key == companion.get_session_key():
            logger.info(f"Established key: {self._session_key}")
        else:
            logger.error(f"Key didn't establish")


if __name__ == "__main__":
    VC = ORVerificationCenter()
    counter = get_random_bytes(2 * BLOCK_LENGTH)
    Alice = ORClient(counter)
    Bob = ORClient(counter)
    Alice.register(VC)
    Bob.register(VC)
    Alice.send_m0_to_companion(Bob, VC)
    Eva = ORClient(counter, usr_id=Bob.get_id())
    Eva.register(VC)
    Alice.send_m0_to_companion(Eva, VC)
    Eva.send_m0_to_companion(Alice, VC)
