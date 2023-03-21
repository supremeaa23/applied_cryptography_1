from DH import initialize_params, get_key
import uuid
import logging
import gmpy2
from random import randint
from GOST3410 import get_public_key, get_dgst, sign_data, verify_signature

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("AKE1-eg Protocol")


def distribute_keys(user: "AKE2egUser", server: "AKE2egServer"):
    msg = user.send_msg()
    msg = server.response_msg(msg)
    user.verify_and_configure_session_key(msg)


class AKE2egUser:
    def __init__(self, p, g, usr_id: uuid.UUID = None):
        self._p = p
        self._g = g
        self._usr_id = usr_id if usr_id else uuid.uuid4()
        self._cert = None
        self._public_key = None
        self._sign_public_key = None
        self._session_key = None
        self._power = None

    def set_power(self):
        self._power = randint(1, self._p - 2)

    def set_public_key(self):
        self.set_power()
        self._public_key = gmpy2.to_binary(gmpy2.powmod(self._g, self._power, self._p))

    def get_signature(self, data):
        public_key, prv = get_public_key()
        self._sign_public_key = public_key
        self._cert = [self._usr_id.bytes, public_key]
        signature = sign_data(data_for_signing=data, prv=prv)
        logger.info(f"User {self._usr_id} formed signature")
        return signature

    def send_msg(self):
        self.set_public_key()
        return [self._public_key, self.get_signature(self._public_key), self._cert]

    def verify_and_configure_session_key(self, msg):
        cp_public_key = msg[0]
        signature = msg[1]
        cp_cert = msg[2]
        dgst = get_dgst(self._public_key + cp_public_key + self._usr_id.bytes)
        if verify_signature(pub=cp_cert[1], signature=signature, dgst=dgst):
            logger.info("SIGNATURE CONFIRMED")
        else:
            logger.error("SIGNATURE REJECTED")
            logger.info(f"Key did not established")
            return
        self._session_key = get_key(gmpy2.powmod(gmpy2.from_binary(cp_public_key), self._power, self._p))
        logger.info(f"User {self._usr_id} established session key {self._session_key.hex()}")


class AKE2egServer:
    def __init__(self, p, g, usr_id: uuid.UUID = None):
        self._p = p
        self._g = g
        self._usr_id = usr_id if usr_id else uuid.uuid4()
        self._cert = None
        self._public_key = None
        self._sign_public_key = None
        self._session_key = None
        self._power = None

    def set_power(self):
        self._power = randint(1, self._p - 2)

    def set_public_key(self):
        self.set_power()
        self._public_key = gmpy2.to_binary(gmpy2.powmod(self._g, self._power, self._p))

    def get_signature(self, data):
        public_key, prv = get_public_key()
        self._sign_public_key = public_key
        self._cert = [self._usr_id.bytes, public_key]
        signature = sign_data(data_for_signing=data, prv=prv)
        logger.info(f"User {self._usr_id} formed signature")
        return signature

    def response_msg(self, msg):
        cp_public_key = msg[0]
        cp_signature = msg[1]
        cp_cert = msg[2]
        dgst = get_dgst(cp_public_key)
        if verify_signature(pub=cp_cert[1], signature=cp_signature, dgst=dgst):
            logger.info("SIGNATURE CONFIRMED")
        else:
            logger.error("SIGNATURE REJECTED")
            logger.info(f"Key did not established")
            return
        self.set_public_key()
        data = cp_public_key + self._public_key + cp_cert[0]
        signature = self.get_signature(data)
        self._session_key = get_key(gmpy2.powmod(gmpy2.from_binary(cp_public_key), self._power, self._p))
        logger.info(f"User {self._usr_id} established session key {self._session_key.hex()}")
        return [self._public_key, signature, self._cert]


if __name__ == "__main__":
    p, g = initialize_params()
    Alice = AKE2egUser(p=p, g=g)
    Bob = AKE2egServer(p=p, g=g)
    distribute_keys(Alice, Bob)
