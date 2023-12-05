from pygost.gost34112012256 import new


def streebog_str(data: str):
    return new(data.encode()).hexdigest()

def streebog_bytes(data: bytes):
    return new(data).hexdigest()

