import logging
import sys
from pygost.gost34112012256 import GOST34112012256

EXIT_CODE = 1

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("Password Access Protocol")


def streebog_hash(value: bytes) -> bytes:
    hash_obj = GOST34112012256()
    hash_obj.update(value)
    return hash_obj.digest()


class PAPServer:
    def __init__(self):
        self._user_db = {}  # user's login&pass store. {login: hash(pass)}

    def register_user(self, usr_login: str, usr_pass: str):
        logger.info(f"Starting user {usr_login} registration")
        if usr_login in self._user_db:
            raise PAPSeverException(f"User {usr_login} registration is failed")
        hash_usr_pass = streebog_hash(usr_pass.encode())
        self._user_db[usr_login] = hash_usr_pass
        logger.info(f"User {usr_login} registration is finished")

    def verify_user(self, usr_login: str, usr_pass: str) -> bool:
        if usr_login not in self._user_db:
            logger.info(f"No user {usr_login}")
            return False

        hash_usr_pass = streebog_hash(usr_pass.encode())
        if hash_usr_pass == self._user_db[usr_login]:
            return True
        else:
            logger.info(f"Wrong password for user {usr_login}")
            return False


class PAPClient:
    def __init__(self, usr_login, usr_pass):
        self._usr_login = usr_login
        self._usr_pass = usr_pass

    def register_user(self, server: PAPServer) -> None:
        try:
            server.register_user(self._usr_login, self._usr_pass)
        except PAPException as err:
            logging.error(err)
            sys.exit(EXIT_CODE)

    def login_user(self, server: PAPServer):
        verify_status = server.verify_user(self._usr_login, self._usr_pass)
        if verify_status:
            logger.info(f"User {self._usr_login} auth: SUCCESS")
        else:
            logger.info(f"User {self._usr_login} auth: FAIL")


class PAPException(Exception):
    pass


class PAPSeverException(Exception):
    pass


if __name__ == "__main__":
    try:
        server = PAPServer()
        alice = PAPClient("Alice", "P@ssw0rd")
        eve = PAPClient("Alice", "Password")
        alice.register_user(server)
        alice.login_user(server)
        eve.login_user(server)
    except Exception as exp:
        logging.exception(exp)
        sys.exit(EXIT_CODE)
