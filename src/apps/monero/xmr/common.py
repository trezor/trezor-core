#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


from trezor.crypto import monero, random


class XmrException(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


def random_bytes(by):
    """
    Generates X random bytes, returns byte-string
    :param by:
    :return:
    """
    return random.bytes(by)


def ct_equal(a, b):
    """
    Constant time a,b comparison
    :param a:
    :param b:
    :return:
    """
    return monero.ct_equals(a, b)


def memcpy(dst, dst_from, src, src_from, length):
    from trezor.utils import memcpy

    return memcpy(dst, dst_from, src, src_from, length)


def check_permutation(permutation):
    """
    Check permutation sanity
    :param permutation:
    :return:
    """
    for n in range(len(permutation)):
        if n not in permutation:
            raise ValueError("Invalid permutation")


def apply_permutation(permutation, swapper):
    """
    Apply permutation from idx. Used for in-place permutation application with swapper.
    Ported from Monero.
    :param permutation:
    :param swapper: function(x,y)
    :return:
    """
    check_permutation(permutation)
    perm = list(permutation)
    for i in range(len(perm)):
        current = i
        while i != perm[current]:
            nxt = perm[current]
            swapper(current, nxt)
            perm[current] = current
            current = nxt
        perm[current] = current


def is_empty(inp):
    """
    True if none or empty
    :param inp:
    :return:
    """
    return inp is None or len(inp) == 0


def defval(val, default=None):
    """
    Returns val if is not None, default instead
    :param val:
    :param default:
    :return:
    """
    return val if val is not None else default


def defval_empty(val, default=None):
    """
    Returns val if is not None, default instead
    :param val:
    :param default:
    :return:
    """
    return val if not is_empty(val) else default


def chunk(arr, size=1):
    res = []
    idx = 0
    while True:
        c = arr[idx : idx + size]
        res.append(c)
        idx += size
        if len(c) != size:
            break
    return res
