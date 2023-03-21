from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
from random import randint
import math
from Crypto.Util.number import getStrongPrime, inverse,bytes_to_long, long_to_bytes
import gmpy2


PRIME_BIT_SIZE = 512
KEY_LENGTH = 32
HKDF_MASTER = b'\x00' * 16


def initialize_params(bits_length: int = 1024):
    p = gmpy2.mpz(getStrongPrime(bits_length))
    g = randint(2, p - 2)
    return p, g


def distribute_keys(user_1: "DHUser",  user_2: "DHUser"):
    user_1.set_power()
    user_2.set_power()
    user_1.send_u(user_2)
    user_2.send_u(user_1)


def get_key(data):
    return HKDF(HKDF_MASTER, KEY_LENGTH, long_to_bytes(data), SHA512, 1)


class DHUser:
    def __init__(self, p, g):
        self._p = p
        self._g = g
        self._power = None
        self._session_key = None

    def set_power(self):
        self._power = randint(1, self._p - 2)

    def send_u(self, companion: "DHUser"):
        companion.set_session_key(gmpy2.powmod(self._g, self._power, self._p))

    def set_session_key(self, u):
        self._session_key = get_key(gmpy2.powmod(u, self._power, self._p))
        print(self._session_key.hex())



if __name__ == "__main__":
    p, g = initialize_params()
    Alice = DHUser(p, g)
    Bob = DHUser(p, g)
    distribute_keys(Alice, Bob)
