from DH import initialize_params, get_key
import uuid
import logging
from Crypto.Random import get_random_bytes
import gmpy2
from random import randint
from GOST3410 import get_public_key, get_dgst, sign_data, verify_signature

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("AKE1-eg Protocol")


RANDOM_LENGTH = 16

def distribute_keys(user: "AKE1egUser", server: "AKE1egServer"):
    user.set_cert()
    server.set_cert()
    user.set_nonce()
    msg = user.send_msg()
    msg = server.response_msg(msg)
    user.get_msg(msg)


class AKE1egUser:
    def __init__(self, p, g, usr_id: uuid.UUID = None,):
        self._db = {} # {id: public_key(g^b)}
        self._usr_id = usr_id if usr_id else uuid.uuid4()
        self._cert = list()
        self._nonce = None
        self._session_key = None
        self._p = p
        self._g = g
        self._power = None
        self._public_key = None

    def set_cert(self):
        self.set_power()
        self._public_key = gmpy2.to_binary(gmpy2.powmod(self._g, self._power, self._p))
        self._cert = [self._usr_id.bytes, self._public_key]

    def set_power(self):
        self._power = randint(1, self._p - 2)

    def set_nonce(self):
        self._nonce = get_random_bytes(RANDOM_LENGTH)
        logger.info(f"User {self._usr_id} generated nonce: {self._nonce.hex()}")

    def send_msg(self):
        return [self._nonce, self._cert]

    def get_msg(self, msg):
        cp_public_key = msg[0]
        signature = msg[1]
        cp_cert = msg[2]
        dgst = get_dgst(self._nonce + cp_public_key + self._usr_id.bytes)
        if verify_signature(pub=cp_cert[1], signature=signature, dgst=dgst):
            logger.info("SIGNATURE CONFIRMED")
        else:
            logger.error("SIGNATURE REJECTED")
            logger.info(f"Key did not established")
            return
        data = self._public_key + cp_public_key + \
               gmpy2.to_binary(gmpy2.powmod(gmpy2.from_binary(cp_public_key), self._power, self._p)) + cp_cert[0]
        key = get_key(gmpy2.from_binary(data))
        logger.info(f"Key established: {key.hex()}")


class AKE1egServer:
    def __init__(self, p, g, usr_id: uuid.UUID = None,):
        self._db = {} # {id: [r, public_key(g^a)]}
        self._usr_id = usr_id if usr_id else uuid.uuid4()
        self._cert = list()
        self._session_key = None
        self._p = p
        self._g = g
        self._power = None
        self._public_key = None

    def set_power(self):
        self._power = randint(1, self._p - 2)

    def set_cert(self):
        self.set_power()
        self._public_key = gmpy2.to_binary(gmpy2.powmod(self._g, self._power, self._p))
        self._cert = [self._usr_id.bytes, None]

    def add_usr(self, msg):
        self._db[msg[1][0]] = [msg[0], msg[1][1]]

    def response_msg(self, msg):
        self.add_usr(msg)
        signature = self.get_signature(msg[0] + self._public_key + msg[1][0])
        data = msg[1][1] + self._public_key + gmpy2.to_binary(gmpy2.powmod(gmpy2.from_binary(msg[1][1]), self._power, self._p)) + self._usr_id.bytes
        key = get_key(gmpy2.from_binary(data))
        logger.info(f"Key established: {key.hex()}")
        return [self._public_key, signature, self._cert]

    def get_signature(self, data):
        public_key, prv = get_public_key()
        self._cert[1] = public_key
        signature = sign_data(data_for_signing=data, prv=prv)
        logger.info(f"User {self._usr_id} formed signature")
        return signature


if __name__ == "__main__":
    p, g = initialize_params()
    Alice = AKE1egUser(p=p, g=g)
    Bob = AKE1egServer(p=p, g=g)
    distribute_keys(Alice, Bob)
