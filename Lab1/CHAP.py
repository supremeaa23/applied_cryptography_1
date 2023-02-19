import logging
import sys
from pygost.gost34112012256 import GOST34112012256
from Crypto.Random import get_random_bytes
from typing import Dict

EXIT_CODE = 1

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("Password Access Protocol")


def streebog_hash(*args: bytes) -> bytes:
    hash_obj = GOST34112012256()
    for value in args:
        hash_obj.update(value)
    return hash_obj.digest().hex()


class CHAPServer:
    def __init__(self):
        self._user_db = {}  # user login&pass store. {login: pass}
        self._user_secrets = {}  # user login&secret store. {login: secret}

    def register_user(self, usr_login: str, usr_pass: str) -> None:
        logger.info(f"Starting user {usr_login} registration")
        if usr_login in self._user_db:
            logger.info(f"User {usr_login} already exists")
            return None
        self._user_db[usr_login] = usr_pass
        logger.info(f"User {usr_login} registration is finished")

    def verify_user(self, usr_login: str, usr_digest: bytes) -> bool:
        if usr_login not in self._user_db:
            logger.info(f"No user {usr_login}")
            return False
        try:
            digest = streebog_hash(usr_login.encode(), self._user_secrets[usr_login])
        except KeyError:
            return False
        if digest == usr_digest:
            return True
        else:
            return False

    def add_user_secret(self, login: str, secret: bytes) -> None:
        if login in self._user_secrets:
            logger.info(f"Secret for user {login} already defined")
        self._user_secrets[login] = secret


class CHAPClient:
    def __init__(self, usr_login: str, usr_pass: str):
        self._usr_login = usr_login
        self._usr_pass = usr_pass
        self._usr_secret = None

    def get_usr_login(self):
        return self._usr_login

    def define_secret(self, server: CHAPServer) -> None:
        self._usr_secret = get_random_bytes(16)
        server.add_user_secret(self._usr_login, self._usr_secret)

    def register_user(self, server: CHAPServer) -> None:
        server.register_user(self._usr_login, self._usr_pass)

    def login_user(self, server: CHAPServer) -> None:
        if self._usr_secret is not None:
            digest = streebog_hash(self._usr_login.encode(), self._usr_secret)
            verify_status = server.verify_user(self._usr_login, digest)
        else:
            logger.info("User's secret not define")
            verify_status = False
        if verify_status:
            logger.info(f"User {self._usr_login} auth: SUCCESS")
        else:
            logger.info(f"User {self._usr_login} auth: FAIL")


if __name__ == "__main__":
    try:
        server = CHAPServer()
        alice = CHAPClient("Alice", "P@ssw0rd")
        eve = CHAPClient("Alice", "Password")
        alice.define_secret(server)
        eve.define_secret(server)
        alice.register_user(server)
        eve.register_user(server)
        alice.login_user(server)
        eve.login_user(server)
    except Exception as exp:
        logger.exception(exp)
        sys.exit(EXIT_CODE)
