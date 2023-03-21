from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
from random import randint
from Crypto.Util.number import getStrongPrime, long_to_bytes
import gmpy2
import logging
import uuid


PRIME_BIT_SIZE = 512
KEY_LENGTH = 32
HKDF_MASTER = b'\x00' * 16

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("Diffie Hellman Protocol")


def initialize_params(bits_length: int = 1024):
    # иницилизация p, q
    p = gmpy2.mpz(getStrongPrime(bits_length))
    g = randint(2, p - 2)
    return p, g


def distribute_keys(user_1: "DHUser",  user_2: "DHUser"):
    # обмен ключами
    # задаются степени, передаются открытые ключи, формируется сессионный ключ
    user_1.set_power()
    user_2.set_power()
    user_1.send_u(user_2)
    user_2.send_u(user_1)

def distribute_keys_with_mallory(user_1: "DHUser", user_2: "DHUser", mallory: "DHUser"):
    # обмен ключами с противником, противник подслушивает ответ, получает открытый ключ, пытается
    # сформировать сессионный ключ
    user_1.set_power()
    user_2.set_power()
    mallory.set_power()
    logger.info("Valid key")
    user_1.send_u(user_2)
    logger.info("Valid key")
    user_2.send_u(user_1)
    logger.info("Invalid key")
    user_1.send_u(mallory)


def get_key(data):
    # HKDF
    return HKDF(HKDF_MASTER, KEY_LENGTH, long_to_bytes(data), SHA512, 1)


class DHUser:
    # класс пользователя
    def __init__(self, p, g, usr_id=None):
        self._usr_id = usr_id if usr_id else uuid.uuid4()
        self._p = p
        self._g = g
        self._power = None
        self._session_key = None

    def set_power(self):
        # генерируем степень
        self._power = randint(1, self._p - 2)

    def send_u(self, companion: "DHUser"):
        # передаем открытый ключ
        logger.info(f"User {self._usr_id} sent public key")
        companion.set_session_key(gmpy2.powmod(self._g, self._power, self._p))

    def set_session_key(self, u):
        # формируем сессионый ключ
        self._session_key = get_key(gmpy2.powmod(u, self._power, self._p))
        logger.info(f"Session key established: {self._session_key.hex()}")


if __name__ == "__main__":
    p, g = initialize_params()
    Alice = DHUser(p, g)
    Bob = DHUser(p, g)
    distribute_keys(Alice, Bob)
    logger.info('-' * 90)
    Mallory = DHUser(p, g)
    distribute_keys_with_mallory(user_1=Alice, user_2=Bob, mallory=Mallory)
