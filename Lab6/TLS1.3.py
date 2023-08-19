import hashlib
import pickle
import uuid
import logging
from pygost import gost3410
from GOST3410 import get_public_key, get_dgst, sign_data, verify_signature
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getStrongPrime, bytes_to_long, long_to_bytes
from random import randint
import gmpy2
import hmac
from typing import Union

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("TLS Protocol")

STRONG_PRIME_SIZE = 512
HKDF_MASTER = b'\x00' * 16
KEY_LENGTH = 16
LEN_MAC = 32


class AESGSM:
    # шифрование и дешифрование AES в режиме GSM
    def __init__(self, key):
        self._key = key

    def encrypt(self, plaintext):
        cipher = AES.new(self._key, AES.MODE_GCM)
        return cipher.nonce, *cipher.encrypt_and_digest(plaintext)

    def decrypt(self, nonce, ciphertext, tag):
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)


def configure_keys_1(prv, u, v, offer, client_nonce, mode, server_nonce):
    # конфигурация ключей для шифрования и хеширования для сервера и клиента
    data = gmpy2.to_binary(prv) + gmpy2.to_binary(u) + gmpy2.to_binary(v) + offer + client_nonce + mode + server_nonce
    ksh, ksm, kch, kcm = HKDF(HKDF_MASTER, KEY_LENGTH, data, SHA256, 4)
    return ksh, ksm, kch, kcm


def configure_keys_2(prv, u, v, offer, client_nonce, mode, server_nonce, c1, c2, c3, c4):
    # конфигурация сеансовых ключей для сервера и клиента
    data = gmpy2.to_binary(prv) + gmpy2.to_binary(u) + gmpy2.to_binary(v) + offer + client_nonce + mode + server_nonce \
           + pickle.dumps(c1) + pickle.dumps(c2) + pickle.dumps(c3) + pickle.dumps(c4)
    kcs, ksc = HKDF(HKDF_MASTER, KEY_LENGTH, data, SHA256, 2)
    return kcs, ksc


def update_keys(kcs, ksc):
    # обновление сессионных ключей сервера и клиента
    return HKDF(HKDF_MASTER, KEY_LENGTH, kcs, SHA256, 1), HKDF(HKDF_MASTER, KEY_LENGTH, ksc, SHA256, 1)


class DiffieHellmanProtocol:
    # класс протокола диффи хеллмана в конечных группах
    def __init__(self, group=None, generator=None):
        self._group = gmpy2.mpz(getStrongPrime(STRONG_PRIME_SIZE)) if group is None else group
        self._generator = randint(2, self._group - 2) if generator is None else generator
        self._power = None

    def get_group(self):
        return self._group

    def get_generator(self):
        return self._generator

    def generate_power(self):
        self._power = randint(1, self._group - 2)

    def configure_public_key(self):
        return gmpy2.powmod(self._generator, self._power, self._group)

    def configure_private_key(self, u):
        return gmpy2.powmod(u, self._power, self._group)


class EllipticDiffieHellmanProtocol:
    # класс протокола диффи хеллмана в элиптических кривых
    def __init__(self, curve=None, generator=None):
        self._curve = gost3410.CURVES['id-tc26-gost-3410-2012-512-paramSetA'] if curve is None else curve
        self._generator = (self._curve.x, self._curve.y) if generator is None else generator
        self._group = self._curve.p
        self._private_key = None

    def multiply_by_scalar(self, curve, scalar, point):
        return curve.exp(scalar, *point)

    def add_points(self, curve, lhs, rhs):
        return curve._add(*lhs, *rhs)

    def generate_private_key(self):
        self._private_key = randint(int(2), int(self._group - 2))
        return self._private_key

    def configure_public_key(self, private_key):
        self._public_key = self.exponentiate(private_key, self._generator)
        return self.element_to_mpz(self.exponentiate(private_key, self._generator))

    def configure_general_key(self, user_public_key):
        user_public_key = self.mpz_to_element(user_public_key)
        return self.element_to_mpz(self.exponentiate(self._private_key, user_public_key))

    def exponentiate(self, scalar, element):
        if not self._curve.contains(element):
            return None
        return self.multiply_by_scalar(self._curve, scalar, element)

    def element_to_mpz(self, element):
        return gmpy2.mpz(bytes_to_long(pickle.dumps(element)))

    def mpz_to_element(self, element):
        return pickle.loads(long_to_bytes(element))


class TLSClient1:
    # 1 клиент с диффи хеллманов в конечных группах
    def __init__(self, ca: "CertificationAuthority"):
        self._id = uuid.uuid4()
        self._signature_public_key, self._signature_private_key = get_public_key()
        self._signature = sign_data(data_for_signing=self._id.bytes, prv=self._signature_private_key)
        self._offer = ["PRIME:AES-GSM:HMAC-SHA256"]
        self._nonce = get_random_bytes(64)
        self._db = {}
        self._dh = None
        self._aes = None
        self._ca = ca
        self._certificate = None
        self._server_ciphertext = []

    def establish_connection(self, server: "TLSServer"):
        # установка соединения с сервером
        # генерируем публичный ключ и отправляем серверу ключ, случайное число и выбранные примитивы
        self._dh = DiffieHellmanProtocol()
        self._dh.generate_power()
        pub_key = self._dh.configure_public_key()
        self._db["dh public key"] = pub_key
        self._offer.append(self._dh.get_group())
        self._offer.append(self._dh.get_generator())
        msg = [pub_key, self._nonce, self._offer]
        server.get_msg(self, msg)

    def get_id(self):
        return self._id

    def get_msgs(self, msgs):
        # получаем от сервера публичный ключ, случайное число, режим
        # 4 шифртекста
        server_dh_public_key = msgs[0]
        self._db["server dh public key"] = server_dh_public_key
        server_nonce = msgs[1]
        self._db["server nonce"] = server_nonce
        server_mode = msgs[2]
        if server_mode != self._offer[0]:
            raise ModeError("Modes don't match.")
        self.configure_keys(server_dh_public_key=server_dh_public_key,
                            server_nonce=server_nonce)
        c1 = msgs[3]
        self._server_ciphertext.append(c1)
        plaintext_1 = self.decrypt_msg(c1)
        c2 = msgs[4]
        self._server_ciphertext.append(c2)
        plaintext_2 = self.decrypt_msg(c2)
        cert = pickle.loads(plaintext_2)
        self.verify_server_certificate(cert)
        c3 = msgs[5]
        self._server_ciphertext.append(c3)
        plaintext_3 = self.decrypt_msg(c3)
        signature_server_public_key = cert[1]
        signature = plaintext_3
        self.verify_signature(signature=signature,
                              signature_server_public_key=signature_server_public_key,
                              server_dh_public_key=server_dh_public_key,
                              server_nonce=server_nonce,
                              c1=c1,
                              c2=c2)
        c4 = msgs[6]
        self._server_ciphertext.append(c4)
        plaintext_4 = self.decrypt_msg(c4)
        self.verify_hmac(server_dh_public_key=server_dh_public_key,
                         server_nonce=server_nonce,
                         c1=c1,
                         c2=c2,
                         c3=c3,
                         check_hmac=plaintext_4)

    def configure_keys(self, server_dh_public_key, server_nonce):
        # конфигурируем ключи для шифрования и хеширования
        dh_prv_key = self._dh.configure_private_key(server_dh_public_key)
        self._db["dh_prv_key"] = self._dh.configure_private_key(server_dh_public_key)
        Ksh, Ksm, Kch, Kcm = configure_keys_1(prv=dh_prv_key,
                                              u=self._db["dh public key"],
                                              client_nonce=self._nonce,
                                              offer=self._offer[0].encode(),
                                              v=server_dh_public_key,
                                              server_nonce=server_nonce,
                                              mode=self._offer[0].encode())
        self._db["Ksh"] = Ksh
        self._db["Ksm"] = Ksm
        self._db["Kch"] = Kch
        self._db["Kcm"] = Kcm
        logger.info(f'''Client {client.get_id()} configured keys with server:
                        Ksh: {Ksh.hex()},
                        Ksm: {Ksm.hex()},
                        Kch: {Kch.hex()},
                        Kcm: {Kcm.hex()}''')
        self._aes = AESGSM(key=Kch)

    def decrypt_msg(self, ciphertext):
        # расшифровка сообщений сервера
        aes_dec = AESGSM(key=self._db["Ksh"])
        nonce, ciph, tag = ciphertext
        plain_text = aes_dec.decrypt(nonce=nonce, ciphertext=ciph, tag=tag)
        return plain_text

    def verify_server_certificate(self, cert):
        # подтверждение сертификата
        server_id = cert[0]
        server_signature_public_key = cert[1]
        server_signature = cert[2]
        verify_signature(pub=server_signature_public_key,
                         signature=server_signature,
                         dgst=get_dgst(server_id.bytes))
        if not verify_signature:
            raise CAIdentificationsError("Signature wasn't confirmed.")
        if self._ca.certificate_is_revoked(cert):
            raise CAIdentificationsError("Certificate is revoked.")
        logger.info("Server certificate is confirmed.")

    def verify_signature(self, signature, signature_server_public_key, server_dh_public_key, server_nonce, c1, c2):
        # подтверждение подписи
        dgst = gmpy2.to_binary(self._db["dh public key"]) + self._nonce + self._offer[0].encode() + \
               gmpy2.to_binary(server_dh_public_key) + \
               self._offer[0].encode() + server_nonce + pickle.dumps(c1) + pickle.dumps(c2)
        if not verify_signature(pub=signature_server_public_key,
                                signature=signature,
                                dgst=get_dgst(dgst)):
            raise CAIdentificationsError("Signature wasn't confirmed.")
        logger.info("Signature is confirmed")

    def verify_hmac(self, server_dh_public_key, server_nonce, c1, c2, c3, check_hmac):
        # подтверждение кода аутентификации
        data = gmpy2.to_binary(self._db["dh public key"]) + self._nonce + self._offer[0].encode() + \
               gmpy2.to_binary(server_dh_public_key) + \
               self._offer[0].encode() + server_nonce + pickle.dumps(c1) + pickle.dumps(c2) + pickle.dumps(c3)
        hm_hash = hmac.new(key=self._db["Ksm"], msg=data, digestmod=hashlib.sha256).hexdigest()
        if hm_hash.encode() == check_hmac:
            logger.info("HMAC is confirmed.")
        else:
            logger.info("HMAC is revoted.")

    def request_certificate_for_usr(self):
        # запрос сертификата у УЦ
        cert = self._ca.configure_participant_certificate(participant_id=self._id,
                                                          participant_signature=self._signature,
                                                          participant_public_key=self._signature_public_key)
        self._certificate = cert

    def send_msgs(self, server):
        # отправляем 3 шифртекста
        msgs = []
        c5 = self.configure_c5()
        c6 = self.configure_c6(c5)
        c7 = self.configure_c7(c5, c6)
        msgs.append(c5)
        msgs.append(c6)
        msgs.append(c7)
        server.get_msgs(self, msgs)

    def configure_c5(self):
        # конфигурием с5
        c5 = self._aes.encrypt(pickle.dumps(self._certificate))
        return c5

    def configure_c6(self, c5):
        # конфигурируем с6
        data = gmpy2.to_binary(self._db["dh public key"]) + self._nonce + self._offer[0].encode() + \
        gmpy2.to_binary(self._db["server dh public key"]) + \
        self._offer[0].encode() + self._db["server nonce"] + pickle.dumps(self._server_ciphertext[0]) + \
        pickle.dumps(self._server_ciphertext[1]) + pickle.dumps(self._server_ciphertext[2]) + \
        pickle.dumps(self._server_ciphertext[3]) + pickle.dumps(c5)
        signature = sign_data(data_for_signing=data, prv=self._signature_private_key)
        c5 = self._aes.encrypt(signature)
        return c5

    def configure_c7(self, c5, c6):
        # конфигурирем с7
        data = gmpy2.to_binary(self._db["dh public key"]) + self._nonce + self._offer[0].encode() + \
               gmpy2.to_binary(self._db["server dh public key"]) + \
               self._offer[0].encode() + self._db["server nonce"] + pickle.dumps(self._server_ciphertext[0]) + \
               pickle.dumps(self._server_ciphertext[1]) + pickle.dumps(self._server_ciphertext[2]) + \
               pickle.dumps(self._server_ciphertext[3]) + pickle.dumps(c5) + pickle.dumps(c6)
        hm_hash = hmac.new(key=self._db["Kcm"], msg=data, digestmod=hashlib.sha256).hexdigest()
        c7 = self._aes.encrypt(hm_hash.encode())
        return c7

    def configure_session_keys(self):
        # конфигурируем сессионные ключи
        Kcs, Ksc = configure_keys_2(prv=self._db["dh_prv_key"],
                                    u=self._db["dh public key"],
                                    v=self._db["server dh public key"],
                                    offer=self._offer[0].encode(),
                                    client_nonce=self._nonce,
                                    mode=self._offer[0].encode(),
                                    server_nonce=self._db["server nonce"],
                                    c1=self._server_ciphertext[0],
                                    c2=self._server_ciphertext[1],
                                    c3=self._server_ciphertext[2],
                                    c4=self._server_ciphertext[3])
        self._db["Kcs"] = Kcs
        self._db["Ksc"] = Ksc
        logger.info(f'''Client {client.get_id()} configured session keys with server: 
                     Kc->s: {Kcs.hex()},
                     Ks->c: {Ksc.hex()}''')

    def send_name(self, server: "TLSServer"):
        # отправляем имя
        try:
            aes_ciph = AESGSM(key=self._db["Kcs"])
            ciph_msg = aes_ciph.encrypt("Bob".encode())
            logger.info("Send message 'Bob'")
            enc_resp = server.send_hello(self, ciph_msg)
            aes_dec = AESGSM(key=self._db["Ksc"])
            plain_resp = aes_dec.decrypt(enc_resp[0], enc_resp[1], enc_resp[2])
            logger.info(f"Get message {plain_resp.decode()}")
        except KeyError:
            raise RequestsError("Mallory detected")

    def get_update(self, msg):
        # обновляем сеансовые ключи
        aes_dec = AESGSM(key=self._db["Ksc"])
        plain_resp = aes_dec.decrypt(msg[0], msg[1], msg[2])
        if plain_resp != b"KeyUpdate":
            raise RequestsError("Non valid request.")
        kcs, ksc = update_keys(kcs=self._db["Kcs"],
                               ksc=self._db["Ksc"])
        self._db["Kcs"] = kcs
        self._db["Ksc"] = ksc
        logger.info("Keys updated")

    def update_key(self, server):
        # отправляем запрос на обновление сеансовых ключей
        aes_ciph = AESGSM(key=self._db["Kcs"])
        cipher_msg = aes_ciph.encrypt(b"KeyUpdate")
        kcs, ksc = update_keys(kcs=self._db["Kcs"],
                               ksc=self._db["Ksc"])
        self._db["Kcs"] = kcs
        self._db["Ksc"] = ksc
        server.get_update(self, cipher_msg)


class TLSClient2:
    # тот же самый клиент, только с диффи хеллманом на элиптических кривых
    # отличается только функция establish_connection использованием другого класса
    def __init__(self, ca: "CertificationAuthority"):
        self._id = uuid.uuid4()
        self._signature_public_key, self._signature_private_key = get_public_key()
        self._signature = sign_data(data_for_signing=self._id.bytes, prv=self._signature_private_key)
        self._offer = ["ELLIPTIC:AES-GSM:HMAC-SHA256"]
        self._nonce = get_random_bytes(64)
        self._db = {}
        self._dh = None
        self._aes = None
        self._ca = ca
        self._certificate = None
        self._server_ciphertext = []

    def establish_connection(self, server: "TLSServer"):
        self._dh = EllipticDiffieHellmanProtocol()
        pub_key = self._dh.configure_public_key(self._dh.generate_private_key())
        self._db["dh public key"] = pub_key
        self._offer.append(self._dh._curve)
        self._offer.append(self._dh._generator)
        msg = [pub_key, self._nonce, self._offer]
        server.get_msg(self, msg)

    def get_id(self):
        return self._id

    def get_msgs(self, msgs):
        server_dh_public_key = msgs[0]
        self._db["server dh public key"] = server_dh_public_key
        server_nonce = msgs[1]
        self._db["server nonce"] = server_nonce
        server_mode = msgs[2]
        if server_mode != self._offer[0]:
            raise ModeError("Modes don't match.")
        self.configure_keys(server_dh_public_key=server_dh_public_key,
                            server_nonce=server_nonce)
        c1 = msgs[3]
        self._server_ciphertext.append(c1)
        plaintext_1 = self.decrypt_msg(c1)
        c2 = msgs[4]
        self._server_ciphertext.append(c2)
        plaintext_2 = self.decrypt_msg(c2)
        cert = pickle.loads(plaintext_2)
        self.verify_server_certificate(cert)
        c3 = msgs[5]
        self._server_ciphertext.append(c3)
        plaintext_3 = self.decrypt_msg(c3)
        signature_server_public_key = cert[1]
        signature = plaintext_3
        self.verify_signature(signature=signature,
                              signature_server_public_key=signature_server_public_key,
                              server_dh_public_key=server_dh_public_key,
                              server_nonce=server_nonce,
                              c1=c1,
                              c2=c2)
        c4 = msgs[6]
        self._server_ciphertext.append(c4)
        plaintext_4 = self.decrypt_msg(c4)
        self.verify_hmac(server_dh_public_key=server_dh_public_key,
                         server_nonce=server_nonce,
                         c1=c1,
                         c2=c2,
                         c3=c3,
                         check_hmac=plaintext_4)

    def configure_keys(self, server_dh_public_key, server_nonce):
        try:
            dh_prv_key = self._dh.configure_private_key(server_dh_public_key)
        except AttributeError:
            dh_prv_key = self._dh.configure_general_key(server_dh_public_key)
        self._db["dh_prv_key"] = dh_prv_key
        Ksh, Ksm, Kch, Kcm = configure_keys_1(prv=dh_prv_key,
                                              u=self._db["dh public key"],
                                              client_nonce=self._nonce,
                                              offer=self._offer[0].encode(),
                                              v=server_dh_public_key,
                                              server_nonce=server_nonce,
                                              mode=self._offer[0].encode())
        self._db["Ksh"] = Ksh
        self._db["Ksm"] = Ksm
        self._db["Kch"] = Kch
        self._db["Kcm"] = Kcm
        logger.info(f'''Client {client.get_id()} configured keys with server:
                        Ksh: {Ksh.hex()},
                        Ksm: {Ksm.hex()},
                        Kch: {Kch.hex()},
                        Kcm: {Kcm.hex()}''')
        self._aes = AESGSM(key=Kch)

    def decrypt_msg(self, ciphertext):
        aes_dec = AESGSM(key=self._db["Ksh"])
        nonce, ciph, tag = ciphertext
        plain_text = aes_dec.decrypt(nonce=nonce, ciphertext=ciph, tag=tag)
        return plain_text

    def verify_server_certificate(self, cert):
        server_id = cert[0]
        server_signature_public_key = cert[1]
        server_signature = cert[2]
        verify_signature(pub=server_signature_public_key,
                         signature=server_signature,
                         dgst=get_dgst(server_id.bytes))
        if not verify_signature:
            raise CAIdentificationsError("Signature wasn't confirmed.")
        if self._ca.certificate_is_revoked(cert):
            raise CAIdentificationsError("Certificate is revoked.")
        logger.info("Server certificate is confirmed.")

    def verify_signature(self, signature, signature_server_public_key, server_dh_public_key, server_nonce, c1, c2):
        dgst = gmpy2.to_binary(self._db["dh public key"]) + self._nonce + self._offer[0].encode() + \
               gmpy2.to_binary(server_dh_public_key) + \
               self._offer[0].encode() + server_nonce + pickle.dumps(c1) + pickle.dumps(c2)
        if not verify_signature(pub=signature_server_public_key,
                                signature=signature,
                                dgst=get_dgst(dgst)):
            raise CAIdentificationsError("Signature wasn't confirmed.")
        logger.info("Signature is confirmed")

    def verify_hmac(self, server_dh_public_key, server_nonce, c1, c2, c3, check_hmac):
        data = gmpy2.to_binary(self._db["dh public key"]) + self._nonce + self._offer[0].encode() + \
               gmpy2.to_binary(server_dh_public_key) + \
               self._offer[0].encode() + server_nonce + pickle.dumps(c1) + pickle.dumps(c2) + pickle.dumps(c3)
        hm_hash = hmac.new(key=self._db["Ksm"], msg=data, digestmod=hashlib.sha256).hexdigest()
        if hm_hash.encode() == check_hmac:
            logger.info("HMAS is confirmed.")
        else:
            logger.info("HMAC is revoted.")

    def configure_session_keys(self):
        Kcs, Ksc = configure_keys_2(prv=self._db["dh_prv_key"],
                                    u=self._db["dh public key"],
                                    v=self._db["server dh public key"],
                                    offer=self._offer[0].encode(),
                                    client_nonce=self._nonce,
                                    mode=self._offer[0].encode(),
                                    server_nonce=self._db["server nonce"],
                                    c1=self._server_ciphertext[0],
                                    c2=self._server_ciphertext[1],
                                    c3=self._server_ciphertext[2],
                                    c4=self._server_ciphertext[3])
        self._db["Kcs"] = Kcs
        self._db["Ksc"] = Ksc
        logger.info(f'''Client {client.get_id()} configured session keys with server: 
                     Kc->s: {Kcs.hex()},
                     Ks->c: {Ksc.hex()}''')

    def send_name(self, server: "TLSServer"):
        aes_ciph = AESGSM(key=self._db["Kcs"])
        ciph_msg = aes_ciph.encrypt("Bob".encode())
        logger.info("Send message 'Bob'")
        enc_resp = server.send_hello(self, ciph_msg)
        aes_dec = AESGSM(key=self._db["Ksc"])
        plain_resp = aes_dec.decrypt(enc_resp[0], enc_resp[1], enc_resp[2])
        logger.info(f"Get message {plain_resp.decode()}")

    def get_update(self, msg):
        aes_dec = AESGSM(key=self._db["Ksc"])
        plain_resp = aes_dec.decrypt(msg[0], msg[1], msg[2])
        if plain_resp != b"KeyUpdate":
            raise RequestsError("Non valid request.")
        kcs, ksc = update_keys(kcs=self._db["Kcs"],
                               ksc=self._db["Ksc"])
        self._db["Kcs"] = kcs
        self._db["Ksc"] = ksc
        logger.info("Keys updated")

    def update_key(self, server):
        aes_ciph = AESGSM(key=self._db["Kcs"])
        cipher_msg = aes_ciph.encrypt(b"KeyUpdate")
        kcs, ksc = update_keys(kcs=self._db["Kcs"],
                               ksc=self._db["Ksc"])
        self._db["Kcs"] = kcs
        self._db["Ksc"] = ksc
        server.get_update(self, cipher_msg)


class TLSServer:
    def __init__(self, ca):
        self._id = uuid.uuid4()
        self._db = {}
        self._ca = ca
        self._aes = None
        self._nonce = get_random_bytes(64)
        self._ciphertexts = []

    def register_user(self, user: Union[TLSClient1, TLSClient2]):
        # регистрируем пользователя
        self.add_user_to_db(user)
        self.configure_signature_keys_and_signature_for_user(user)
        self.request_certificate_for_usr(user)

    def add_user_to_db(self, user: Union[TLSClient1, TLSClient2]):
        # добавляем пользователя в базу данных
        if user.get_id() in self._db:
            raise RegisterUserErrors(f"User {user.get_id} was already registered.")
        self._db[user.get_id()] = {}

    def configure_signature_keys_and_signature_for_user(self, user: Union[TLSClient2, TLSClient1]):
        # конфигурием подпись и ключи
        if user.get_id() not in self._db:
            raise RegisterUserErrors(f"User {user.get_id} wasn't registered.")
        signature_public_key, signature_private_key = get_public_key()
        self._db[user.get_id()]["server signature public_key"] = signature_public_key
        self._db[user.get_id()]["server signature private key"] = signature_private_key
        signature = sign_data(data_for_signing=self._id.bytes, prv=signature_private_key)
        self._db[user.get_id()]["server signature"] = signature

    def request_certificate_for_usr(self, user):
        # запрашиваем сертификат
        cert = self._ca.configure_participant_certificate(participant_id=self._id,
                                                          participant_signature=self._db[user.get_id()]
                                                          ["server signature"],
                                                          participant_public_key=self._db[user.get_id()]
                                                          ["server signature public_key"])
        self._db[user.get_id()]["server certificate"] = cert

    def get_msg(self, user: [TLSClient1, TLSClient2], msg):
        # получаем первое сообщение от пользователя
        usr_pub_key = msg[0]
        usr_nonce = msg[1]
        usr_offer = msg[2]
        usr_mode = usr_offer[0]
        usr_group = usr_offer[1]
        usr_generator = usr_offer[2]
        if usr_mode.split(':')[0] == "ELLIPTIC":
            dh = EllipticDiffieHellmanProtocol(generator=usr_generator, curve=usr_group)
            server_dh_public_key = dh.configure_public_key(dh.generate_private_key())
            dh_private_key = dh.configure_general_key(usr_pub_key)
        else:
            dh = DiffieHellmanProtocol(group=usr_group, generator=usr_generator)
            dh.generate_power()
            server_dh_public_key = dh.configure_public_key()
            dh_private_key = dh.configure_private_key(usr_pub_key)
        self._db[user.get_id()]["usr_pub_key"] = usr_pub_key
        self._db[user.get_id()]["mode"] = usr_mode
        self._db[user.get_id()]["client nonce"] = usr_nonce
        self._db[user.get_id()]["dh private key"] = dh_private_key
        self._db[user.get_id()]["server dh public key"] = server_dh_public_key

    def configure_keys(self, user):
        # конфигурием ключи для шифрования и выработки кода аутентификации
        Ksh, Ksm, Kch, Kcm = configure_keys_1(prv=self._db[user.get_id()]["dh private key"],
                                              u=self._db[user.get_id()]["usr_pub_key"],
                                              client_nonce=self._db[user.get_id()]["client nonce"],
                                              offer=self._db[user.get_id()]["mode"].encode(),
                                              v=self._db[user.get_id()]["server dh public key"],
                                              mode=self._db[user.get_id()]["mode"].encode(),
                                              server_nonce=self._nonce)
        self._db[user.get_id()]["Ksh"] = Ksh
        self._db[user.get_id()]["Ksm"] = Ksm
        self._db[user.get_id()]["Kch"] = Kch
        self._db[user.get_id()]["Kcm"] = Kcm
        logger.info(f'''Server configured keys with client {user.get_id()}:
                        Ksh: {Ksh.hex()},
                        Ksm: {Ksm.hex()},
                        Kch: {Kch.hex()},
                        Kcm: {Kcm.hex()}''')
        self._aes = AESGSM(key=Ksh)

    def send_msgs(self, user: Union[TLSClient2, TLSClient1]):
        # конфигурируем и отправляем клиенту шифртексты, открытый ключ, случайное число и режим
        msgs = []
        msgs.append(self._db[user.get_id()]["server dh public key"])
        msgs.append(self._nonce)
        msgs.append(self._db[user.get_id()]["mode"])
        c1 = self.configure_c1()
        if self._db[user.get_id()]["mode"].split(':')[0] == 'ELLIPTIC':
            c1 = self.configure_empty_c1()
        c2 = self.configure_c2(user)
        c3 = self.configure_c3(user, c1, c2)
        c4 = self.configure_c4(user, c1, c2, c3)
        msgs.append(c1)
        msgs.append(c2)
        msgs.append(c3)
        msgs.append(c4)
        self._ciphertexts = [c1, c2, c3, c4]
        user.get_msgs(msgs)

    def configure_c1(self):
        # конфигурием с1
        req = "Need certificate".encode()
        c1 = self._aes.encrypt(req)
        return c1

    def configure_empty_c1(self):
        # пустой с1
        req = " ".encode()
        c1 = self._aes.encrypt(req)
        return c1

    def configure_c2(self, user):
        # конфигурием с2
        c2 = self._aes.encrypt(pickle.dumps(self._db[user.get_id()]["server certificate"]))
        return c2

    def configure_c3(self, user, c1, c2):
        # конфигурием с3
        data = gmpy2.to_binary(self._db[user.get_id()]["usr_pub_key"]) + self._db[user.get_id()]["client nonce"] + \
               self._db[user.get_id()]["mode"].encode() + \
               gmpy2.to_binary(self._db[user.get_id()]["server dh public key"]) + \
               self._db[user.get_id()]["mode"].encode() + self._nonce + pickle.dumps(c1) + pickle.dumps(c2)
        signature = sign_data(data_for_signing=data, prv=self._db[user.get_id()]["server signature private key"])
        c3 = self._aes.encrypt(signature)
        return c3

    def configure_c4(self, user, c1, c2, c3):
        # конфигурием с4
        data = gmpy2.to_binary(self._db[user.get_id()]["usr_pub_key"]) + self._db[user.get_id()]["client nonce"] + \
               self._db[user.get_id()]["mode"].encode() + \
               gmpy2.to_binary(self._db[user.get_id()]["server dh public key"]) + \
               self._db[user.get_id()]["mode"].encode() + self._nonce + pickle.dumps(c1) + pickle.dumps(c2) \
               + pickle.dumps(c3)
        hm_hash = hmac.new(key=self._db[user.get_id()]["Ksm"], msg=data, digestmod=hashlib.sha256).hexdigest()
        c4 = self._aes.encrypt(hm_hash.encode())
        return c4

    def get_msgs(self, user, msgs):
        # принимаем от пользователя 3 шифртекста
        c5 = msgs[0]
        user_cert = pickle.loads(self.decrypt_msg(user, c5))
        self.verify_user_certificate(user_cert)
        c6 = msgs[1]
        signature = self.decrypt_msg(user, c6)
        user_signature_public_key = user_cert[1]
        self.verify_signature(user=user,
                              user_signature_public_key=user_signature_public_key,
                              signature=signature,
                              c5=c5)
        c7 = msgs[2]
        hm_hash = self.decrypt_msg(user, c7)
        self.verify_hmac(user=user,
                         c5=c5,
                         c6=c6,
                         check_hmac=hm_hash)

    def decrypt_msg(self, user, ciphertext):
        # расшифровываем сообщения пользователя
        aes_dec = AESGSM(key=self._db[user.get_id()]["Kch"])
        nonce, ciph, tag = ciphertext
        plain_text = aes_dec.decrypt(nonce=nonce, ciphertext=ciph, tag=tag)
        return plain_text

    def verify_user_certificate(self, user_cert):
        # подтверждаем сертификат пользователя
        user_id = user_cert[0]
        user_signature_public_key = user_cert[1]
        user_signature = user_cert[2]
        verify_signature(pub=user_signature_public_key,
                         signature=user_signature,
                         dgst=get_dgst(user_id.bytes))
        if not verify_signature:
            raise CAIdentificationsError("Signature wasn't confirmed.")
        if self._ca.certificate_is_revoked(user_cert):
            raise CAIdentificationsError("Certificate is revoked.")
        self._db[user_id]["user cert"] = user_cert
        logger.info("User certificate is confirmed.")

    def verify_signature(self, user, user_signature_public_key, signature, c5):
        # подтверждаем подпись пользователя
        dgst = gmpy2.to_binary(self._db[user.get_id()]["usr_pub_key"]) + self._db[user.get_id()]["client nonce"] + \
               self._db[user.get_id()]["mode"].encode() + \
               gmpy2.to_binary(self._db[user.get_id()]["server dh public key"]) + \
               self._db[user.get_id()]["mode"].encode() + self._nonce + pickle.dumps(self._ciphertexts[0]) + \
               pickle.dumps(self._ciphertexts[1]) + pickle.dumps(self._ciphertexts[2]) + \
               pickle.dumps(self._ciphertexts[3]) + pickle.dumps(c5)
        if not verify_signature(pub=user_signature_public_key,
                                signature=signature,
                                dgst=get_dgst(dgst)):
            raise CAIdentificationsError("Signature wasn't confirmed.")
        logger.info("Signature is confirmed")

    def verify_hmac(self, user, c5, c6, check_hmac):
        # подтверждаем код аутентификации пользователя
        data = gmpy2.to_binary(self._db[user.get_id()]["usr_pub_key"]) + self._db[user.get_id()]["client nonce"] + \
               self._db[user.get_id()]["mode"].encode() + \
               gmpy2.to_binary(self._db[user.get_id()]["server dh public key"]) + \
               self._db[user.get_id()]["mode"].encode() + self._nonce + pickle.dumps(self._ciphertexts[0]) + \
               pickle.dumps(self._ciphertexts[1]) + pickle.dumps(self._ciphertexts[2]) + \
               pickle.dumps(self._ciphertexts[3]) + pickle.dumps(c5) + pickle.dumps(c6)
        hm_hash = hmac.new(key=self._db[user.get_id()]["Kcm"], msg=data, digestmod=hashlib.sha256).hexdigest()
        if hm_hash.encode() == check_hmac:
            logger.info("HMAC is confirmed.")
        else:
            logger.info("HMAC is revoted.")

    def configure_session_keys(self, user):
        # конфигурием сессионные ключи
        Kcs, Ksc = configure_keys_2(prv=self._db[user.get_id()]["dh private key"],
                                    u=self._db[user.get_id()]["usr_pub_key"],
                                    v=self._db[user.get_id()]["server dh public key"],
                                    offer=self._db[user.get_id()]["mode"].encode(),
                                    client_nonce=self._db[user.get_id()]["client nonce"],
                                    mode=self._db[user.get_id()]["mode"].encode(),
                                    server_nonce=self._nonce,
                                    c1=self._ciphertexts[0],
                                    c2=self._ciphertexts[1],
                                    c3=self._ciphertexts[2],
                                    c4=self._ciphertexts[3])
        self._db[user.get_id()]["Kcs"] = Kcs
        self._db[user.get_id()]["Ksc"] = Ksc
        logger.info(f'''Server configured session keys with client {user.get_id()}: 
                     Kc->s: {Kcs.hex()},
                     Ks->c: {Ksc.hex()}''')

    def send_hello(self, user, encrypt_msg):
        # отвечаем на сообщения пользователя
        aes_dec = AESGSM(key=self._db[user.get_id()]["Kcs"])
        plain_msg = aes_dec.decrypt(nonce=encrypt_msg[0],
                                    ciphertext=encrypt_msg[1],
                                    tag=encrypt_msg[2])
        aes_ciph = AESGSM(key=self._db[user.get_id()]["Ksc"])
        cipher_msg = aes_ciph.encrypt(b"Hello, " + plain_msg)
        return cipher_msg

    def update_key(self, user):
        # обновляем ключи
        aes_ciph = AESGSM(key=self._db[user.get_id()]["Ksc"])
        cipher_msg = aes_ciph.encrypt(b"KeyUpdate")
        kcs, ksc = update_keys(kcs=self._db[user.get_id()]["Kcs"],
                               ksc=self._db[user.get_id()]["Ksc"])
        self._db[user.get_id()]["Kcs"] = kcs
        self._db[user.get_id()]["Ksc"] = ksc
        user.get_update(cipher_msg)

    def get_update(self, user, msg):
        # получаем запрос на обновление ключей и обновляем ключи
        aes_dec = AESGSM(key=self._db[user.get_id()]["Kcs"])
        plain_resp = aes_dec.decrypt(msg[0], msg[1], msg[2])
        if plain_resp != b"KeyUpdate":
            raise RequestsError("Non valid request.")
        kcs, ksc = update_keys(kcs=self._db[user.get_id()]["Kcs"],
                               ksc=self._db[user.get_id()]["Ksc"])
        self._db[user.get_id()]["Kcs"] = kcs
        self._db[user.get_id()]["Ksc"] = ksc
        logger.info("Keys updated")


class CertificationAuthority:
    def __init__(self):
        self._certificates_repository = []  # [{id: cert}]
        self._revoked_certificates_repository = []  # [{id: cert}]
        self._public_signature_key, self._private_signature_key = get_public_key()

    def get_public_key(self):
        return self._public_signature_key

    def configure_participant_certificate(self, participant_id, participant_signature, participant_public_key):
        # конфигурием сертификат для участника
        self._authenticate_participant(participant_id=participant_id,
                                       participant_signature=participant_signature,
                                       participant_public_key=participant_public_key)
        cert = [participant_id, participant_public_key, sign_data(data_for_signing=participant_id.bytes,
                                                                  prv=self._private_signature_key)]
        self._certificates_repository.append({participant_id: cert})
        return cert

    def revoke_participant_certificate(self, participant_id, participant_signature, participant_public_key, cert):
        # обнуляем сертификат участника
        self._authenticate_participant(participant_id=participant_id,
                                       participant_signature=participant_signature,
                                       participant_public_key=participant_public_key)
        cert_for_revoke = cert

        if {participant_id: cert_for_revoke} not in self._certificates_repository:
            logger.info(f"Participant {participant_id} has no certificate for revoke.")
            return

        self._revoked_certificates_repository.append({[participant_id]: cert_for_revoke})
        new_certificates_rep = []
        for elem in self._certificates_repository:
            if elem != {[participant_id]: cert_for_revoke}:
                new_certificates_rep.append(elem)
        self._certificates_repository = new_certificates_rep
        logger.info(f"Participant {participant_id} certificate was revoked.")

    def certificate_is_revoked(self, cert):
        # проверяем, обнулен ли сертификат
        return cert in self._revoked_certificates_repository

    def _authenticate_participant(self, participant_id, participant_public_key, participant_signature):
        # проверяем участника
        dgst = get_dgst(participant_id.bytes)
        if verify_signature(pub=participant_public_key,
                            signature=participant_signature,
                            dgst=dgst):
            logger.info(f"Participant {participant_id} private key knowledge was approved.")
        else:
            raise CAIdentificationsError(f"Participant {participant_id} private key knowledge was refuted.")

    @staticmethod
    def _get_participant_params(participant):
        return participant.get_id(), participant.get_public_key(), participant.get_signature()


class TLSProtocolExceptions(Exception):
    pass


class RegisterUserErrors(TLSProtocolExceptions):
    pass


class CAIdentificationsError(TLSProtocolExceptions):
    pass


class ModeError(TLSProtocolExceptions):
    pass


class RequestsError(TLSProtocolExceptions):
    pass


if __name__ == "__main__":
    try:
        ca = CertificationAuthority()
        # PRIME
        logger.info("Prime")
        client = TLSClient1(ca)
        server = TLSServer(ca)
        server.register_user(client)
        client.establish_connection(server)
        server.configure_keys(client)
        server.send_msgs(client)
        client.configure_session_keys()
        client.request_certificate_for_usr()
        client.send_msgs(server)
        server.configure_session_keys(user=client)
        client.send_name(server)
        server.update_key(client)
        client.send_name(server)
        client.update_key(server)
        client.send_name(server)
        logger.info("Elliptic")
        # Elliptic
        client = TLSClient1(ca)
        server = TLSServer(ca)
        server.register_user(client)
        client.establish_connection(server)
        server.configure_keys(client)
        server.send_msgs(client)
        client.configure_session_keys()
        client.request_certificate_for_usr()
        client.send_msgs(server)
        server.configure_session_keys(user=client)
        client.send_name(server)
        server.update_key(client)
        client.send_name(server)
        client.update_key(server)
        client.send_name(server)
        # fake
        logger.info("Mallory")
        mallory = TLSClient1(ca)
        mallory._id = client.get_id()
        mallory.send_name(server)
    except RequestsError as err:
        logger.error(err)
