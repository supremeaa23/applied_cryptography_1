import logging
import sys
from pygost.gost34112012256 import GOST34112012256
from Crypto.Random import get_random_bytes

EXIT_CODE = 1

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("Challenge-Handshake Authentication Protocol")


def streebog_hash(*args: bytes) -> bytes:
    # Функция хеширования алгоритмом "Стрибог".
    hash_obj = GOST34112012256()
    for value in args:
        hash_obj.update(value)
    return hash_obj.digest().hex()


class CHAPServer:
    # Класс выступает в роли сервера.
    # Иницилизируется "база данных" пользователей {логин: [пароль, случайное число клиента]},
    # Задаются логин и пароль сервера.
    # Задается пустым значением случайное число, получаемое от клиента
    def __init__(self):
        self._user_db = {}  # user login&pass store. {login: [pass, ran_num]}

    def register_user(self, usr_login: str, usr_pass: str) -> None:
        # Функция регистрации пользователя. На вход принимается логин и пароль клиента.
        # С помощью клиента получаем логин и пароль пользователя
        # Если логин есть в базе, то регистрация прекращается
        # Если логина нет в базе данных, то создаем запись с пустым случайным числом
        logger.info(f"Starting user {usr_login} registration")
        if usr_login in self._user_db:
            logger.info(f"User {usr_login} already exists")
            return None
        self._user_db[usr_login] = [usr_pass, None]
        logger.info(f"User {usr_login} registration is finished")

    def verify_user(self, usr_login: str, usr_digest: bytes) -> bool:
        # Функция проверки данных пользователя. На вход принимается логин и сформированный дайжест клиента.
        # Если логина нет в базе, то авторизация прекращается, возвращается False.
        # Формируется дайджест из пароля пользователя и случайного числа.
        # Если дайджест совпадает, то авторизация прошла успешно, возвращается True. В противном случае False.
        # Если пользователь нашелся в базе, то при завершении авторизации дайджест обнуляется.
        if usr_login not in self._user_db:
            logger.info(f"No user {usr_login}")
            return False
        try:
            digest = streebog_hash(self._user_db[usr_login][0].encode(), self._user_db[usr_login][1])
        except KeyError:
            self._user_db[usr_login][1] = None
            return False
        if digest == usr_digest:
            self._user_db[usr_login][1] = None
            return True
        else:
            self._user_db[usr_login][1] = None
            return False

    def get_random_number(self, client: "CHAPClient") -> None:
        # Функция генерации случайного числа. На вход принимается объект клиента.
        # Если логин пользователя не находится в базе данных, то нет смысла генерировать случайное число.
        # Если пользователь есть в базе данных, проверяется наличие случайного числа, отнесенного к этому пользователю.
        # Если числа нет, то оно формируется, заносится в базу сервера и передается пользователю.
        if client.get_usr_login() in self._user_db:
            if self._user_db[client.get_usr_login()][1] is None:
                ran_num = get_random_bytes(16)
                self._user_db[client.get_usr_login()][1] = ran_num
                client.set_ran_num(ran_num)
                logger.info(f"Random number for user {client.get_usr_login()} was generated")
            else:
                logger.info(f"Random number already exists")
        else:
            logger.info(f"No user named {client.get_usr_login()}")


class CHAPClient:
    # Класс выступает в роли Клиента.
    # Иницилизируются логин, пароль, случайное число, которое будет получено от сервера.
    def __init__(self, usr_login: str, usr_pass: str):
        self._usr_login = usr_login
        self._usr_pass = usr_pass
        self._ran_num = None

    def get_usr_login(self) -> str:
        # получение логина
        return self._usr_login

    def set_ran_num(self, ran_num) -> None:
        # установка случайного числа
        self._ran_num = ran_num

    def register_user(self, server: CHAPServer) -> None:
        # регистрация пользователя на сервере
        server.register_user(self._usr_login, self._usr_pass)

    def login_user(self, server: CHAPServer) -> None:
        # авторизация пользователя.
        # если случайное число получено от сервера, то формируется дайджест и передается серверу на проверку.
        # Если дайджест прошел проверку, то авторизация прошла успешно, в противном случае авторизация провалена.
        if self._ran_num is not None:
            digest = streebog_hash(self._usr_pass.encode(), self._ran_num)
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
        alice.register_user(server)
        eve.register_user(server)
        server.get_random_number(alice)
        alice.login_user(server)
        server.get_random_number(eve)
        eve.login_user(server)
        server.get_random_number(alice)
        alice.login_user(server)
        server.get_random_number(eve)
        eve.login_user(server)
    except Exception as exp:
        logger.exception(exp)
        sys.exit(EXIT_CODE)
