import sys
from typing import List, Union
from pygost.gost34112012256 import GOST34112012256
import logging
from Crypto.Random import get_random_bytes

EXIT_CODE = 1
ROUNDS = 3

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("S/KEY")


def passwords_generator(passwd: bytes, random_num: bytes, rounds: int) -> List[bytes]:
    # функция генерации паролей
    # возвращает список из раундовых паролей
    key_list = list()
    pair = passwd + random_num

    for _ in range(rounds):
        pair = streebog_hash(pair)
        key_list.append(pair)
    return key_list


def streebog_hash(*args: bytes) -> bytes:
    # Функция хеширования алгоритмом "Стрибог".
    hash_obj = GOST34112012256()
    for value in args:
        hash_obj.update(value)
    return hash_obj.digest()


class SKEYServer:
    # Класс выступает в роли сервера.
    # Иницилизируются база данных пользователя, раунды
    def __init__(self):
        '''
            {
                login: 
                        {
                            password: password,
                            transaction_number: transaction_number,
                            random_num: random_num,
                            key_list: key_list,
                            current_key: current_key
                        }
            }
        '''
        self._rounds = None
        self._users_db = {}

    def register_user(self, client: "SKEYClient") -> Union[bytes, None]:
        # функция регистрации пользователя.
        # Получаем креды пользователя, количество раундов.
        # Если логин пользователя есть в бд, то не регистрируем.
        # В противном случае создаем запись в бд.
        usr_login, usr_pass = client.get_credits()
        self._rounds = client.get_rounds()
        logger.info(f"Starting user {usr_login} registration")
        if usr_login in self._users_db:
            logger.info(f"User {usr_login} already exists")
            return None
        self._users_db[usr_login] = {
            "password": usr_pass.encode(),
            "transaction_number": 1,
            "random_num": None,
            "key_list": [],
            "current_key": None
        }
        self._set_ran_num(usr_login)
        self._set_key_list_and_current_key(usr_login)
        return self._users_db[usr_login]["random_num"]

    def verify_user(self, client: "SKEYClient", current_key: bytes) -> Union[bool, None]:
        # Функция проверки авторизации пользователя. Проверка провалена только когда возвращается False
        # Получаем логин пользователя, если пользователя нет в бд, то авторизация провалена.
        # Если сессионный пароль не совпадает с тем, что в бд, то авторизация провалена. Возвращаем False.
        # Получаем статус транзакции. Если все раунды пройдены, возвращаем None (успешная авторизация, но обновляется
        # случайное число.
        # Если авторизация прошла успешно, не все раунды использованы, то обновляется сессионный пароль.
        usr_login, _ = client.get_credits()
        if usr_login not in self._users_db:
            return False

        if current_key != self._users_db[usr_login]["current_key"]:
            return False

        transaction_status = self._update_transaction_number(usr_login)
        if not transaction_status:
            return None

        self._users_db[usr_login]["current_key"] = self._users_db[usr_login]["key_list"][
            -self._users_db[usr_login]["transaction_number"]
        ]
        return True

    def _update_transaction_number(self, usr_login: str) -> bool:
        # Обновляем номер транзакции, если раунды кончились, то возвращаем False.
        self._users_db[usr_login]["transaction_number"] += 1
        if self._users_db[usr_login]["transaction_number"] > self._rounds:
            return False
        return True

    def reset_ran_num(self, client: "SKEYClient"):
        # Обнновляем случайное число, а вместе с ним и список сессионных паролей, сбрасываем транзакцию
        usr_login, _ = client.get_credits()
        self._set_ran_num(usr_login)
        self._set_key_list_and_current_key(usr_login)
        self._users_db[usr_login]["transaction_number"] = 1
        client.set_key_list(self._users_db[usr_login]["key_list"])

    def _set_ran_num(self, login: str) -> None:
        # Устанавливаем случан число
        ran_num = get_random_bytes(16)
        self._users_db[login]["random_num"] = ran_num

    def _set_key_list_and_current_key(self, login: str) -> None:
        # устанавливаем список сессионных паролей и сессионный пароль
        self._users_db[login]["key_list"] = passwords_generator(passwd=self._users_db[login]["password"],
                                                                random_num=self._users_db[login]["random_num"],
                                                                rounds=self._rounds)
        self._users_db[login]["current_key"] = self._users_db[login]["key_list"][-1]


    def get_transaction_number(self, client: "SKEYClient") -> Union[int, None]:
        # получаем номер транзакции
        usr_login, _ = client.get_credits()
        if usr_login not in self._users_db:
            logger.info(f"No user named {usr_login} in database")
            return None
        return self._users_db[usr_login]["transaction_number"]


class SKEYClient:
    # Класс выступает в роли Клиента.
    # Иницилизируется логин, пароль клиента, кол-во раундов, список сессионных паролей
    def __init__(self, usr_login: str, usr_pass: str, rounds: int):
        self._usr_login = usr_login
        self._usr_pass = usr_pass
        self._rounds = rounds
        self._key_list = list()

    def get_credits(self) -> (str, str):
        # получаем креды
        return self._usr_login, self._usr_pass

    def set_key_list(self, key_list: List[bytes]) -> None:
        # устанавливаем сессионные пароли
        self._key_list = key_list

    def get_rounds(self) -> int:
        # получаем раунды
        return self._rounds

    def register_user(self, server: SKEYServer) -> None:
        # регистрируем пользователя. Устанавливаем сессионные пароли
        ran_num = server.register_user(self)
        if ran_num is None:
            return
        self.set_key_list(passwords_generator(passwd=self._usr_pass.encode(), random_num=ran_num, rounds=self._rounds))
        logger.info(f"User {self._usr_login} registered. Key list generated")

    def logging(self, server: SKEYServer):
        # Авторизация пользователя.
        transaction_number = server.get_transaction_number(self)
        if transaction_number is None:
            logger.info("Wrong username")
        verify_result = server.verify_user(self, self._key_list[-transaction_number])
        if verify_result:
            logger.info(f"User {self._usr_login} auth: SUCCESS")
        elif verify_result is None:
            logger.info(f"User {self._usr_login} auth: SUCCESS")
            server.reset_ran_num(self)
        else:
            logger.info(f"Wrong username or password")


if __name__ == "__main__":
    try:
        server = SKEYServer()
        Alice = SKEYClient("Alice", "P@ssw0rd", ROUNDS)
        Eve = SKEYClient("Alice", "Passwird", ROUNDS)
        Alice.register_user(server)
        Eve.register_user(server)
        Eve.set_key_list(passwords_generator(Eve._usr_pass.encode(), b'\x00\x00', 3))
        Alice.logging(server)
        Eve.logging(server)
        Alice.logging(server)
        Alice.logging(server)
        Alice.logging(server)
        Alice.logging(server)
    except Exception as exp:
        logger.exception(exp)
        sys.exit(EXIT_CODE)
