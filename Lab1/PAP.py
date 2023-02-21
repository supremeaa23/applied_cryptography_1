import logging
import sys

EXIT_CODE = 1

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("Password Access Protocol")


class PAPServer:
    def __init__(self):
        self._user_db = {}  # user login&pass store. {login: pass}

    def register_user(self, usr_login: str, usr_pass: str) -> None:
        logger.info(f"Starting user {usr_login} registration")
        if usr_login in self._user_db:
            logger.info(f"User {usr_login} already exists")
            return None
        self._user_db[usr_login] = usr_pass
        logger.info(f"User {usr_login} registration is finished")

    def verify_user(self, usr_login: str, usr_pass: str) -> bool:
        if usr_login not in self._user_db:
            logger.info(f"No user {usr_login}")
            return False

        if usr_pass == self._user_db[usr_login]:
            return True
        else:
            logger.info(f"Wrong password for user {usr_login}")
            return False


class PAPClient:
    def __init__(self, usr_login, usr_pass):
        self._usr_login = usr_login
        self._usr_pass = usr_pass

    def register_user(self, server: PAPServer) -> None:
        server.register_user(self._usr_login, self._usr_pass)

    def login_user(self, server: PAPServer) -> None:
        verify_status = server.verify_user(self._usr_login, self._usr_pass)
        if verify_status:
            logger.info(f"User {self._usr_login} auth: SUCCESS")
        else:
            logger.info(f"User {self._usr_login} auth: FAIL")


if __name__ == "__main__":
    try:
        server = PAPServer()
        alice = PAPClient("Alice", "P@ssw0rd")
        eve = PAPClient("Alice", "Password")
        alice.register_user(server)
        eve.register_user(server)
        alice.login_user(server)
        eve.login_user(server)
    except Exception as exp:
        logging.exception(exp)
        sys.exit(EXIT_CODE)
