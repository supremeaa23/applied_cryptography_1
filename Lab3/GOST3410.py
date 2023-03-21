from pygost.gost3410 import CURVES, prv_unmarshal, public_key, sign, verify, pub_marshal
from pygost import gost34112012512
from pygost.utils import hexenc
from os import urandom

curve = CURVES["id-tc26-gost-3410-12-512-paramSetA"]


def get_public_key():
    prv_raw = urandom(64)
    prv = prv_unmarshal(prv_raw)
    pub = public_key(curve, prv)
    return pub, prv


def get_dgst(data_for_signing):
   return gost34112012512.new(data_for_signing).digest()[::-1]


def sign_data(data_for_signing: bytes, prv):
    dgst = gost34112012512.new(data_for_signing).digest()[::-1]
    signature = sign(curve, prv, dgst)
    return signature


def verify_signature(pub, signature, dgst) -> bool:
    return verify(curve, pub, dgst, signature)


# data = b"sixteen-byte-msg"
# pub, prv = get_public_key()
# signature = sign_data(data, prv)
# print(verify_signature(pub, signature, get_dgst(data)))

