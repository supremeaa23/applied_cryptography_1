import logging
import sys

EXIT_CODE = 1

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("Password Access Protocol")


class PAPServer:  # класс Сервера. Сервер регистрирует пользователя и позволяет осуществлять вход пользователя по паролю
    def __init__(self):  # иницилизируется пустая "база данных" пользователей, представленная в качестве словаря
        self._user_db = {}  # user login&pass store. {login: pass}

    def register_user(self, usr_login: str, usr_pass: str) -> None:
        # Регистрация пользователя. На вход подается логин и пароль пользователя.
        # Если пользователя нет в "базе данных", пользователь регистрируется. В противном случае возвращается None.
        logger.info(f"Starting user {usr_login} registration")
        if usr_login in self._user_db:
            logger.info(f"User {usr_login} already exists")
            return None
        self._user_db[usr_login] = usr_pass
        logger.info(f"User {usr_login} registration is finished")

    def verify_user(self, usr_login: str, usr_pass: str) -> None:
        # Авторизация пользователя по логину и паролю.
        # Если логина пользователя нет в "базе данных", авторизация прерывается, возвращается False.
        # Если пароль, переданный пользователем не совпадает с паролем по данному логину в "базе данных" регистрация
        # прерывается, возвращается False.
        # Если пользователь есть в "базе данных" и переданный пароль совпадает с тем, что хранится в "базе" возвращается True.
        if usr_login not in self._user_db:
            logger.info(f"No user {usr_login}")
            logger.info(f"User {usr_login} auth: FAIL")
        if usr_pass == self._user_db[usr_login]:
            logger.info(f"User {usr_login} auth: SUCCESS")
        else:
            logger.info(f"Wrong password for user {usr_login}")
            logger.info(f"User {usr_login} auth: FAIL")


class PAPClient:
    def __init__(self, usr_login, usr_pass):
        # Класс клиента. Иницилизируется по логину и паролю клиента.
        # Может передавать данные для регистрации пользователя на сервере. Может передавать данные для авторизации
        # пользователя на сервере.
        self._usr_login = usr_login
        self._usr_pass = usr_pass

    def register_user(self, server: PAPServer) -> None:
        # Функция передает серверу логин и пароль пользователя для регистрации
        server.register_user(self._usr_login, self._usr_pass)

    def login_user(self, server: PAPServer) -> None:
        # Авторизация пользователя по логину и паролю
        server.verify_user(self._usr_login, self._usr_pass)


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
