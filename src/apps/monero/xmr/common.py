from trezor.crypto import monero


class XmrException(Exception):
    pass


def ct_equal(a, b):
    return monero.ct_equals(a, b)


def is_empty(inp):
    return inp is None or len(inp) == 0
