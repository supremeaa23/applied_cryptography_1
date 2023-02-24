import logging
import sys
from pygost.gost34112012256 import GOST34112012256
from Crypto.Random import get_random_bytes

EXIT_CODE = 1

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("Modified Challenge-Handshake Authentication Protocol")


def streebog_hash(*args: bytes) -> bytes:
    # Функция хеширования алгоритмом "Стрибог".
    hash_obj = GOST34112012256()
    for value in args:
        hash_obj.update(value)
    return hash_obj.digest().hex()


class ModifiedCHAPServer:
    # Класс выступает в роли сервера.
    # Иницилизируется "база данных" пользователей {логин: [пароль, случайное число клиента]},
    # Задаются логин и пароль сервера.
    # Задается пустым значением случайное число, получаемое от клиента
    def __init__(self):
        self._user_db = {}  # user login&pass store. {login: [pass, client_num]}
        self._login = "Server"
        self._pass = "Server"
        self._client_num = None

    def register_user(self, client: "ModifiedCHAPClient"):
        # Функция регистрации пользователя. На вход принимается объект клиента.
        # С помощью клиента получаем логин и пароль пользователя
        # Если логин есть в базе, то регистрация прекращается
        # Если логина нет в базе данных, то создаем запись с пустым случайным числом клиента и возвращаем креды сервера.
        usr_login, usr_pass = client.get_credits()
        logger.info(f"Starting user {usr_login} registration")
        if usr_login in self._user_db:
            logger.info(f"User {usr_login} already exists")
            return self.get_credits()
        self._user_db[usr_login] = [usr_pass.encode(), None]
        logger.info(f"User {usr_login} registration is finished")
        return self.get_credits()

    def get_credits(self) -> (str, str):
        # функция передачи кред сервера
        return self._login, self._pass

    def set_client_num(self, client_num) -> None:
        # функция установки случайного числа полученного от клиента
        self._client_num = client_num

    def verify_user(self, client: "ModifiedCHAPClient", usr_digest) -> (bytes, None):
        # функция авторизации пользователя
        # получаем креды пользователя
        # если от пользователя было получено случайное число, то формируется дайджест из случайного числа,
        # сгенерированного сервером и паролем пользователя. Дайджест проверяется с присланным пользователем,
        # если дайджест пользователя проходит проверку, то формируется дайджест с паролем сервера и присланным
        # пользователем случайным числом. Дайджест возвращается пользователю, случайные числа на сервере обнуляются.
        usr_login, usr_pass = client.get_credits()
        if self._client_num:
            digest = streebog_hash(self._user_db[usr_login][0], self._user_db[usr_login][1])
            if digest == usr_digest:
                srv_digest = streebog_hash(self._pass.encode(), self._client_num)
                self.reset_num(usr_login)
                return srv_digest
            else:
                self.reset_num(usr_login)
                return None
        else:
            self.reset_num(usr_login)
            return None

    def get_random_number(self, client: "ModifiedCHAPClient") -> None:
        # Функция генерации случайного числа. На вход принимается объект клиента.
        # Если логин пользователя не находится в базе данных, то нет смысла генерировать случайное число.
        # Если пользователь есть в базе данных, проверяется наличие случайного числа, отнесенного к этому пользователю.
        # Если числа нет, то оно формируется, заносится в базу сервера и передается пользователю.
        usr_login, usr_pass = client.get_credits()
        if usr_login in self._user_db:
            if self._user_db[usr_login][1] is None:
                ran_num = get_random_bytes(16)
                self._user_db[usr_login][1] = ran_num
                client.set_server_num(ran_num)
                logger.info(f"Random number for user {usr_login} was generated")
            else:
                logger.info(f"Random number already exists")
        else:
            logger.info(f"No user named {usr_login}")

    def reset_num(self, usr_login: str) -> None:
        # функция обнуления случайных чисел
        self._client_num = None
        self._user_db[usr_login][1] = None


class ModifiedCHAPClient:
    # Класс выступает в роли клиента.
    # Иницилизируются база серверов, логин и пароль пользователя, случайное число, полученное от сервера.
    def __init__(self, usr_login: str, usr_pass: str):
        self._servers_db = {}  # server login&pass store. {login: [pass, server_num]}
        self._usr_login = usr_login
        self._usr_pass = usr_pass
        self._server_num = None

    def register_user(self, server: ModifiedCHAPServer):
        # Функция регистрации пользователя.
        # Получает логин и пароль от сервера, передает свои данные серверу.
        # Если сервера нет в бд, то записывает его креды в бд, случайное число выставляет в None
        serv_login, serv_pass = server.register_user(self)
        if serv_login in self._servers_db:
            logger.info(f"Server's credits already in database")
            return None
        self._servers_db[serv_login] = [serv_pass.encode(), None]

    def logging(self, server: ModifiedCHAPServer):
        # Функция авторизации пользователя
        # Получает креды сервера. Если случайное число от сервера не установлено, то авторизация провалена.
        # Формируется дайджест из случайного числа сервера и пароля пользователя. Отправляеся серверу на проверку.
        # Если сервер вернул другой дайджест, значит проверка прошла успешно и пользователю осталось подтвердить
        # дайджест, полученный от сервера. Если дайджест подтверждается, то авторизация успешна.
        srv_login, srv_pass = server.get_credits()
        if self._server_num is not None:
            srv_digest = streebog_hash(self._usr_pass.encode(), self._server_num)
            self.get_random_number(server)
            usr_digest = server.verify_user(self, srv_digest)
            if usr_digest is not None:
                digest = streebog_hash(self._servers_db[srv_login][0], self._servers_db[srv_login][1])
                if digest == usr_digest:
                    self.reset_num(srv_login)
                    logging.info(f"User {self._usr_login} auth: SUCCESS")
                else:
                    self.reset_num(srv_login)
                    logging.info(f"User {self._usr_login} auth: FAIL")
            else:
                self.reset_num(srv_login)
                logging.info(f"User {self._usr_login} auth: FAIL")
        else:
            self.reset_num(srv_login)
            logger.info("Server's secret not define")
            logger.info(f"User {self._usr_login} auth with: FAIL")

    def get_random_number(self, server: ModifiedCHAPServer):
        # Функция генерации случайного числа. На вход принимается объект сервера.
        # Если логин сервера не находится в базе данных, то нет смысла генерировать случайное число.
        # Если сервер есть в базе данных, проверяется наличие случайного числа, отнесенного к этому серверу.
        # Если числа нет, то оно формируется, заносится в базу пользователя и передается серверу.
        srv_login, srv_pass = server.get_credits()
        if srv_login in self._servers_db:
            if self._servers_db[srv_login][1] is None:
                ran_num = get_random_bytes(16)
                self._servers_db[srv_login][1] = ran_num
                server.set_client_num(ran_num)
                logger.info(f"Random number for server {srv_login} was generated")
            else:
                logger.info(f"Random number already exists")
        else:
            logger.info(f"No server named {srv_login}")

    def set_server_num(self, server_num) -> None:
        # установка случайного числа
        self._server_num = server_num

    def reset_num(self, srv_login: str) -> None:
        # обнуление случайного числа
        self._server_num = None
        self._servers_db[srv_login][1] = None

    def get_credits(self) -> (str, str):
        # получение кред пользователя
        return self._usr_login, self._usr_pass


if __name__ == "__main__":
    try:
        server = ModifiedCHAPServer()
        alice = ModifiedCHAPClient("Alice", "P@ssw0rd")
        eve = ModifiedCHAPClient("Alice", "password")
        alice.register_user(server)
        server.get_random_number(alice)
        alice.logging(server)
        eve.register_user(server)
        server.get_random_number(eve)
        eve.logging(server)
    except Exception as exp:
        logging.exception(exp)
        sys.exit(EXIT_CODE)
