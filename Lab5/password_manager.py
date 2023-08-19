import json
import logging
import os
import sys
import time

from Crypto.Random import get_random_bytes
import hashlib
import hmac
from pygost.gost3412 import GOST3412Kuznechik
from pygost.mgm import MGM
from Crypto.Util.number import long_to_bytes
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("Password Manager")

GREETING = '''
Password Manager
1. Add password for the site;
2. Log in to the site;
3. Change the password;
4. Delete the password;
5. Rollback to the latest version;
6. Exit.
'''
EMPTY_STORAGE = '''
It seems you have never used the password manager yet.
You need come up with a password for using this program.
'''
CHANGE_PASSWORD = "Input the site which password you want to change"
ADD_SITE_AND_PASSWORD = 'Would you like to enter the site and the password? (yes/no)'
GET_PASS_FROM_SITE = "Input the domain name which password you want to know"
DELETE_RECORD = "Input the domain name you want delete"
YES = ["yes", "y", "YES", "Y"]
NO = ["no", "n", "NO", "N"]
USER_FLASH_DRIVE_PATH = "./User flash drive/password_manager.md5"
BACKUP_PATH = "./Backup/"
PASSWORD_STORAGE_PATH = "password storage.json"
DEFAULT_ITEMS = [1, 2, 3, 4, 5, 6]
PASSWORD_SIZE = 64
BLOCK_SIZE = 16
SALT_SIZE = 32
MASTER_SALT = b'46d6b5a8086db7b2836523d651f1bb4bcfd37507a829328654819dd41c3c6084'
K1_SALT = b'047e2f04b3f6e34d660550d13f665da07d91bbac5334cd9cbf9727f5e7c992fb'
K2_SALT = b'55ee5a16bc40b06bd667a197d58577ff4094dd5da3cd4bc44af28d8a005106af'
ITERATIONS_NUMBER = 200000
NONCE = b'\x00' * GOST3412Kuznechik.blocksize
AD = b'\xff' * GOST3412Kuznechik.blocksize


def add_padding(data):
    # добавить паддинг
    if len(data) > PASSWORD_SIZE:
        data = data[:PASSWORD_SIZE]
    padding_size = PASSWORD_SIZE - len(data)
    data += get_random_bytes(padding_size) + long_to_bytes(padding_size)
    return data


def remove_padding(data):
    # удалить паддинг
    padding_size = data[-1]
    data = data[:-padding_size - 1]
    return data


class PasswordManager:
    def __init__(self):
        self._item = None
        self._k1 = None  # for hash
        self._k2 = None  # for encrypt
        self._db = {}
        self._session = None

    def set_session(self, session):
        self._session = session

    def set_item(self, item):
        self._item = item

    def set_db(self, password_data):
        self._db = password_data

    def reset_params(self):
        self._item = None
        self._k1 = None
        self._k2 = None
        self._db = {}

    def save_database(self):
        # сохраняем словарь в файл
        try:
            with open(PASSWORD_STORAGE_PATH, "r") as file:
                backup = json.load(file)
            with open(f"{BACKUP_PATH}{str(datetime.now())}.json", "w") as file:
                json.dump(backup, file)
        except FileNotFoundError:
            pass
        with open(PASSWORD_STORAGE_PATH, "w") as file:
            json.dump(self._db, file)

    def save_md5_hash(self):
        # сохраняем хеш
        md5_hash = self.get_hash_md5()
        with open(USER_FLASH_DRIVE_PATH, "w") as file:
            file.write(md5_hash)

    def check_md5_hash(self):
        # проверка хеша
        try:
            with open(USER_FLASH_DRIVE_PATH, "r") as file:
                saved_md5_value = file.read()
        except FileNotFoundError:
            logger.info("No data about hash, unable to verify integrity")
            return
        with open(PASSWORD_STORAGE_PATH, "r") as file:
            db = json.load(file)
        received_value = self.get_hash_md5()
        if saved_md5_value != received_value:
            for key in db:
                received_hash = hashlib.md5(key.encode() + db[key][0].encode()).hexdigest()
                if received_hash != db[key][1]:
                    raise DatabaseAttacksError("Attack by permutation")
            raise DatabaseAttacksError("Attack by rollback")
        else:
            logger.info(f"Password storage integrity confirmed")

    @staticmethod
    def get_hash_md5():
        # получаем хеш файла
        with open(PASSWORD_STORAGE_PATH, 'rb') as f:
            m = hashlib.md5()
            while True:
                data = f.read(8192)
                if not data:
                    break
                m.update(data)
            return m.hexdigest()

    def set_master_key(self):
        # генерируем мастер ключ
        master_key = input("Input the password: ")
        main_key = hashlib.pbkdf2_hmac(hash_name='sha256',
                                       password=master_key.encode(),
                                       salt=MASTER_SALT,
                                       iterations=ITERATIONS_NUMBER)
        self.configure_keys(main_key)

    def add_record_to_database(self, domain, password):
        # добавить запись в базу данных (новый сайт и пароль к нему)
        hashed_domain = self.get_domain_hash(domain.encode())
        encrypt_password = self.get_encrypt_password(password.encode())
        self._db[hashed_domain] = [encrypt_password,
                                   hashlib.md5(hashed_domain.encode() + encrypt_password.encode()).hexdigest()]
        logger.info(f"Password to the {domain} added in database")

    def rewrite_record_in_database(self, domain):
        # смена пароля для сайта в бд
        hashed_domain = self.get_domain_hash(domain.encode())
        if hashed_domain not in self._db:
            raise EmptyDataError(f"No domain name {domain} in database")
        password = input("Input new password")
        encrypt_password = self.get_encrypt_password(password.encode())
        self._db[hashed_domain] = [encrypt_password,
                                   hashlib.md5(hashed_domain.encode() + encrypt_password.encode()).hexdigest()]

    def get_pass_from_db(self, domain):
        # получаем пароль от выбранного домена из бд
        hashed_domain = self.get_domain_hash(domain.encode())
        if hashed_domain in self._db:
            encrypt_password = self._db[hashed_domain][0]
            password = self.get_decrypt_password(encrypt_password)
            return password
        else:
            raise EmptyDataError(f"No record for {domain} in database")

    def configure_keys(self, main_key):
        # получаем ключи из мастер-ключа
        self._k1 = hmac.new(key=main_key,
                            msg=K1_SALT,
                            digestmod=hashlib.sha256).digest()
        self._k2 = hmac.new(key=main_key,
                            msg=K2_SALT,
                            digestmod=hashlib.sha256).digest()

    def check_master_pass(self):
        # проверяем пароль от менеджера с помощью проверки наличия хешированного домена в бд
        master_key = input("Input the password: ")
        main_key = hashlib.pbkdf2_hmac(hash_name='sha256',
                                       password=master_key.encode(),
                                       salt=MASTER_SALT,
                                       iterations=ITERATIONS_NUMBER)
        existed_domain = input("Input one of the existing in database site: ")
        self.configure_keys(main_key)
        hashed_domain = self.get_domain_hash(existed_domain.encode())
        if hashed_domain not in self._db:
            raise AuthorizationError(f"Password is not correct or no domain {existed_domain} in database")

    def get_domain_hash(self, domain):
        # хешируем домен
        domain_hash = hmac.new(key=self._k1, msg=domain, digestmod=hashlib.sha256).digest().hex()
        return domain_hash

    def get_encrypt_password(self, password):
        # шифруем пароль
        mgm = MGM(GOST3412Kuznechik(self._k2).encrypt,
                  GOST3412Kuznechik.blocksize)
        encrypt_password = mgm.seal(NONCE, add_padding(password), AD)
        return encrypt_password.hex()

    def get_decrypt_password(self, ciphertext):
        # расшифровываем пароль
        mgm = MGM(GOST3412Kuznechik(self._k2).encrypt,
                  GOST3412Kuznechik.blocksize)
        password = mgm.open(NONCE, bytes.fromhex(ciphertext), AD)
        password = remove_padding(password)
        return password

    @staticmethod
    def greeting():
        time.sleep(1)
        print(GREETING)

    def get_item_from_user(self):
        # выбор пользователя
        while True:
            try:
                item = int(input("Select an item: "))
            except ValueError:
                print("Input a digit: ")
                continue
            if item not in DEFAULT_ITEMS:
                print("Input one of the suggested items: ")
                continue
            self.set_item(item)
            break

    def rollback(self):
        # откат к резервным копиям
        backup_names_list = os.listdir(BACKUP_PATH)
        if len(backup_names_list) != 0:
            item = 1
            for backup_name in backup_names_list:
                print(f"{item}. {backup_name}")
                item += 1
            backup_item = int(input("Input the item of backup you want rollback"))
            with open(BACKUP_PATH+backup_names_list[backup_item - 1], 'r') as file:
                backup_db = json.load(file)
            with open(PASSWORD_STORAGE_PATH, "w") as file:
                json.dump(backup_db, file)
            self.save_md5_hash()
        else:
            raise EmptyDataError("No backups")

    def execute(self):
        # главное меню
        if not self._item:
            raise ItemsError("No item was chosen")
        if self._item == DEFAULT_ITEMS[0]:
            self.check_md5_hash()
            self.add_password()
        elif self._item == DEFAULT_ITEMS[1]:
            self.check_md5_hash()
            self.log_in()
        elif self._item == DEFAULT_ITEMS[2]:
            self.check_md5_hash()
            self.change_password()
        elif self._item == DEFAULT_ITEMS[3]:
            self.check_md5_hash()
            self.delete_record()
        elif self._item == DEFAULT_ITEMS[4]:
            self.rollback()
        elif self._item == DEFAULT_ITEMS[5]:
            return self.exit()
        return

    def exit(self,):
        # выход из программы
        self.reset_params()
        return 1

    def add_password(self):
        # вносим пароль для сайта в бд
        try:
            with open(PASSWORD_STORAGE_PATH, "r") as file:
                password_data = json.load(file)
                if len(password_data) == 0:
                    raise FileNotFoundError()
                self.set_db(password_data)
            user_answer = input(ADD_SITE_AND_PASSWORD)
            if user_answer in YES:
                if not self._session:
                    self.check_master_pass()
                    self._session = get_random_bytes(16)
                logger.info("Authorization successful")
            elif user_answer in NO:
                return None
            else:
                return None
        except (json.decoder.JSONDecodeError, FileNotFoundError):
            password_data = {}
            self.set_db(password_data)
            print(EMPTY_STORAGE)
            user_answer = input(ADD_SITE_AND_PASSWORD)
            if user_answer in YES:
                self.set_master_key()
            elif user_answer in NO:
                return None
            else:
                return None
        domain = input("Input the site: ")
        password = input("Input the password: ")
        self.add_record_to_database(domain, password)
        self.save_database()
        self.save_md5_hash()

    def change_password(self):
        # смена пароля для сайта
        try:
            with open(PASSWORD_STORAGE_PATH, "r") as file:
                password_data = json.load(file)
                self.set_db(password_data)
            if not self._session:
                self.check_master_pass()
                self._session = get_random_bytes(16)
            logging.info("Authorization successful")
            domain = input(CHANGE_PASSWORD)
            self.rewrite_record_in_database(domain)
            logger.info(f"Password for {domain} was changed")
            self.save_database()
            self.save_md5_hash()
        except (json.decoder.JSONDecodeError, FileNotFoundError):
            raise EmptyDataError("Database is empty")

    def log_in(self):
        # вывод в stdout пароля от сайта
        try:
            with open(PASSWORD_STORAGE_PATH, "r") as file:
                password_data = json.load(file)
                self.set_db(password_data)
            if not self._session:
                self.check_master_pass()
                self._session = get_random_bytes(16)
            logging.info("Authorization successful")
            domain = input(GET_PASS_FROM_SITE)
            password = self.get_pass_from_db(domain)
            logger.info(f"Password for {domain}: {password.decode('utf-8')}")
        except (json.decoder.JSONDecodeError, FileNotFoundError):
            raise EmptyDataError("Database is empty")

    def delete_record(self):
        # удаление записи из бд
        try:
            with open(PASSWORD_STORAGE_PATH, "r") as file:
                password_data = json.load(file)
                self.set_db(password_data)
            if not self._session:
                self.check_master_pass()
                self._session = get_random_bytes(16)
            logging.info("Authorization successful")
            domain = input(DELETE_RECORD)
            hashed_domain = self.get_domain_hash(domain.encode())
            if hashed_domain in self._db:
                self._db.pop(hashed_domain)
            else:
                logger.info(f"No record for {domain} in database")
                return
            logger.info(f"Domain {domain} was deleted from database")
            self.save_database()
            self.save_md5_hash()
        except (json.decoder.JSONDecodeError, FileNotFoundError):
            raise EmptyDataError("Database is empty")


class PasswordManagerException(Exception):
    pass


class ItemsError(PasswordManagerException):
    pass


class AuthorizationError(PasswordManagerException):
    pass


class EmptyDataError(PasswordManagerException):
    pass


class DatabaseAttacksError(PasswordManagerException):
    pass


if __name__ == "__main__":
    exit_code = 1
    pm = PasswordManager()
    while True:
        try:
            pm.greeting()
            pm.get_item_from_user()
            state = pm.execute()
            if state:
                break
        except ItemsError as err:
            logger.error(err)
        except AuthorizationError as err:
            logger.error(err)
        except EmptyDataError as err:
            logger.error(err)
        except DatabaseAttacksError as err:
            logger.error(err)
        except KeyboardInterrupt:
            sys.exit(0)
        except Exception as exp:
            logger.exception(exp)
            sys.exit(exit_code)
