import sympy
from sympy import Matrix
from math import gcd
from functools import reduce
import logging


logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("GET KEY")


def get_key_by_lagrange_interpolation(users, P):
    def multiply_list_elements(data):
        return reduce(lambda x, y: x * y, data)
    list_for_user_1 = list()
    for user_1 in users:
        list_for_user_2 = list()
        for user_2 in users:
            if user_1.get_point() != user_2.get_point():
                list_for_user_2.append(user_2.get_point() * pow(user_2.get_point() - user_1.get_point(), -1, P))
        list_for_user_1.append(user_1.get_value() * multiply_list_elements(list_for_user_2))
    return sum(list_for_user_1) % P


def get_key_by_eq(users, P):
    try:
        equations = list()
        for user in users:
            equations.append(user.get_eq())

        matrix = Matrix([eq[0] for eq in equations])
        vector = Matrix([eq[1] for eq in equations])

        det = int(matrix.det())

        result = None
        if gcd(det, P) == 1:
            result = pow(det, -1, P) * matrix.adjugate() @ vector % P
        else:
            pass
        return result[0]
    except sympy.matrices.common.NonSquareMatrixError:
        logger.info("Recover key failed")
        logger.info("Attempt to collect key without all participants")
        return None
