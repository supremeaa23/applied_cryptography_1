from sympy import GF, isprime
from random import getrandbits
from math import gcd


def get_params_for_pedersen(q, LENGTH_P):
    def get_group_element(p, q):
        mutual_prime = getrandbits(LENGTH_P)
        while gcd(mutual_prime, p) != 1:
            mutual_prime = getrandbits(LENGTH_P)
        field = GF(p)
        return field(mutual_prime) ** ((p - 1) // q)

    p = getrandbits(LENGTH_P // 2) * q + 1

    while not isprime(p):
        p = getrandbits(LENGTH_P // 2) * q + 1

    g = get_group_element(p, q)
    h = get_group_element(p, q)

    return p, g, h


def get_params_for_feldman(q, LENGTH_P):
    def get_group_element(p, q):
        mutual_prime = getrandbits(LENGTH_P)
        while gcd(mutual_prime, p) != 1:
            mutual_prime = getrandbits(LENGTH_P)
        field = GF(p)
        return field(mutual_prime) ** ((p - 1) // q)

    p = getrandbits(LENGTH_P // 2) * q + 1
    while not isprime(p):
        p = getrandbits(LENGTH_P // 2) * q + 1

    return p, get_group_element(p, q)
