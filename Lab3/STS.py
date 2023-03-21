from DH import initialize_params, get_key
import uuid
import logging
import gmpy2
from random import randint
from GOST3410 import get_public_key, get_dgst, sign_data, verify_signature
from Kuznechik import encrypt_kuznechik, decrypt_kuznechik

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("STS Protocol")

DH_SIZE = 1024
RANDOM_LENGTH = 16


def distribute_keys(user: "STSUser", server: "STSServer"):
    # обмен ключами
    msg = user.send_msg()
    msg = server.response_msg(msg)
    msg = user.response_msg(msg)
    server.verify(msg)

def distribute_keys_with_mallory(user: "STSUser", server: "STSServer", mallory: "STSUser"):
    # обмен ключами с противником
    # противник отвечает на сообщение сервера и пытается сконфигурировать сессионный ключ
    msg = user.send_msg()
    msg = server.response_msg(msg)
    false_msg = mallory.response_msg(msg)
    server.verify(false_msg)


class STSUser:
    # cторона P
    def __init__(self, p, g, usr_id: uuid.UUID = None):
        self._p = p
        self._g = g
        self._power = None
        self._usr_id = usr_id if usr_id else uuid.uuid4()
        self._cert = None
        self._public_key = None
        self._sign_public_key = None
        self._session_key = None

    def set_cert(self):
        self._cert = [self._usr_id, self._sign_public_key]

    def set_public_key(self):
        self._public_key = gmpy2.to_binary(gmpy2.powmod(self._g, self._power, self._p))

    def set_power(self):
        self._power = randint(1, self._p - 2)

    def send_msg(self):
        # отправляем открытый ключ Q
        self.set_power()
        self.set_public_key()
        return self._public_key

    def get_signature(self, data):
        # подпись
        public_key, prv = get_public_key()
        self._sign_public_key = public_key
        self.set_cert()
        signature = sign_data(data_for_signing=data, prv=prv)
        logger.info(f"User {self._usr_id} formed signature")
        return signature

    def response_msg(self, msg):
        # отвечаем на сообщение стороны Q
        # генерируем сессионный ключ
        # проверяем подпись
        cp_public_key = msg[0]
        cipher_text = msg[1]
        cp_id, cp_sign_public_key = msg[2][0], msg[2][1]
        try:
            self._session_key = get_key((gmpy2.powmod(gmpy2.from_binary(cp_public_key), self._power, self._p)))
        except TypeError:
            logger.error("Not enough data to configure session key")
            logger.error("Session key did not established")
            return
        signature = decrypt_kuznechik(key=self._session_key, cipher_text=cipher_text)
        dgst = get_dgst(self._public_key + cp_public_key)
        if verify_signature(pub=cp_sign_public_key, signature=signature, dgst=dgst):
            logger.info("SIGNATURE CONFIRMED")
        else:
            logger.error("SIGNATURE REJECTED")
            logger.info(f"Key did not established")
            return
        logger.info(f"User {self._usr_id} established session key: {self._session_key.hex()}")
        data = self._public_key + cp_public_key
        signature = self.get_signature(data)
        cipher_text = encrypt_kuznechik(key=self._session_key, plain_text=signature)
        return [cipher_text, self._cert]


class STSServer:
    # сторона Q
    def __init__(self, p, g, usr_id: uuid.UUID = None):
        self._p = p
        self._g = g
        self._power = None
        self._usr_id = usr_id if usr_id else uuid.uuid4()
        self._cert = None
        self._public_key = None
        self._sign_public_key = None
        self._session_key = None
        self._companion_public_key = None

    def set_cert(self):
        self._cert = [self._usr_id, self._sign_public_key]

    def set_power(self):
        self._power = randint(1, self._p - 2)

    def set_public_key(self):
        self._public_key = gmpy2.to_binary(gmpy2.powmod(self._g, self._power, self._p))

    def response_msg(self, msg):
        # отвечаем на сообщение Р
        # генерируем сессионный ключ
        self.set_power()
        self.set_public_key()
        self._companion_public_key = msg
        data = msg + self._public_key
        signature = self.get_signature(data)
        self._session_key = get_key((gmpy2.powmod(gmpy2.from_binary(msg), self._power, self._p)))
        logger.info(f"User {self._usr_id} established session key: {self._session_key.hex()}")
        cipher_text = encrypt_kuznechik(key=self._session_key, plain_text=signature)
        return [self._public_key, cipher_text, self._cert]

    def get_signature(self, data):
        # подпись
        public_key, prv = get_public_key()
        self._sign_public_key = public_key
        self.set_cert()
        signature = sign_data(data_for_signing=data, prv=prv)
        logger.info(f"User {self._usr_id} formed signature")
        return signature

    def verify(self, msg):
        # проверяем собеседника
        try:
            cipher_text = msg[0]
        except TypeError:
            logger.error("SIGNATURE REJECTED")
            logger.info(f"FALSE COMPANION")
            return
        cp_id, cp_sign_public_key = msg[1][0], msg[1][1]
        signature = decrypt_kuznechik(key=self._session_key, cipher_text=cipher_text)
        dgst = get_dgst(self._companion_public_key + self._public_key)
        if verify_signature(pub=cp_sign_public_key, signature=signature, dgst=dgst):
            logger.info("SIGNATURE CONFIRMED")
            logger.info("TRUE COMPANION")
        else:
            logger.error("SIGNATURE REJECTED")
            logger.info(f"FALSE COMPANION")


if __name__ == "__main__":
    p, g = initialize_params()
    Alice = STSUser(p=p, g=g)
    Bob = STSServer(p=p, g=g)
    distribute_keys(Alice, Bob)
    logger.info("-" * 90)
    Mallory = STSUser(p=p, g=g)
    distribute_keys_with_mallory(Alice, Bob, Mallory)
