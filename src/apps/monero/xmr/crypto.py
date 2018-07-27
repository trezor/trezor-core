#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018
#
# Resources:
# https://cr.yp.to
# https://github.com/monero-project/mininero
# https://godoc.org/github.com/agl/ed25519/edwards25519
# https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-00#section-4
# https://github.com/monero-project/research-lab

import ubinascii as binascii

from trezor.crypto import hmac, monero as tcry, pbkdf2 as tpbkdf2, random
from trezor.crypto.hashlib import sha3_256

NULL_KEY_ENC = [0] * 32


def random_bytes(by):
    """
    Generates X random bytes, returns byte-string
    :param by:
    :return:
    """
    return random.bytes(by)


def keccak_factory(data=None):
    return sha3_256(data=data, keccak=True)


def get_keccak():
    """
    Simple keccak 256
    :return:
    """
    return keccak_factory()


def keccak_hash(inp):
    """
    Hashesh input in one call
    :return:
    """
    return tcry.xmr_fast_hash(inp)


def keccak_2hash(inp):
    """
    Keccak double hashing
    :param inp:
    :return:
    """
    return keccak_hash(keccak_hash(inp))


def get_hmac(key, msg=None):
    """
    Returns HMAC object (uses Keccak256)
    :param key:
    :param msg:
    :return:
    """
    return hmac.new(key, msg=msg, digestmod=keccak_factory)


def compute_hmac(key, msg=None):
    """
    Computes and returns HMAC of the msg using Keccak256
    :param key:
    :param msg:
    :return:
    """
    h = hmac.new(key, msg=msg, digestmod=keccak_factory)
    return h.digest()


def pbkdf2(inp, salt, length=32, count=1000, prf=None):
    """
    PBKDF2 with default PRF as HMAC-KECCAK-256
    :param inp:
    :param salt:
    :param length:
    :param count:
    :param prf:
    :return:
    """
    pb = tpbkdf2("hmac-sha256", inp, salt)
    pb.update(count)
    return pb.key()


#
# EC
#


def decodepoint(x):
    return tcry.ge25519_unpack_vartime(x)


def encodepoint(pt):
    return tcry.ge25519_pack(pt)


def encodepoint_into(pt, b):
    return tcry.ge25519_pack_into(pt, b)


def decodeint(x):
    return tcry.unpack256_modm(x)


def encodeint(x):
    return tcry.pack256_modm(x)


def encodeint_into(x, b):
    return tcry.pack256_modm_into(x, b)


def check_ed25519point(x):
    return tcry.ge25519_check(x)


def scalarmult_base(a):
    return tcry.ge25519_scalarmult_base(a)


def scalarmult(P, e):
    return tcry.ge25519_scalarmult(P, e)


def point_add(P, Q):
    return tcry.ge25519_add(P, Q, 0)


def point_sub(P, Q):
    return tcry.ge25519_add(P, Q, 1)


def point_eq(P, Q):
    return tcry.ge25519_eq(P, Q)


def point_double(P):
    return tcry.ge25519_double(P)


def point_norm(P):
    """
    Normalizes point after multiplication
    Extended edwards coordinates (X,Y,Z,T)
    :param P:
    :return:
    """
    return tcry.ge25519_norm(P)


#
# Zmod(order), scalar values field
#


def sc_0():
    """
    Sets 0 to the scalar value Zmod(m)
    :return:
    """
    return tcry.init256_modm(0)


def sc_init(x):
    """
    Sets x to the scalar value Zmod(m)
    :return:
    """
    if x >= (1 << 64):
        raise ValueError("Initialization works up to 64-bit only")
    return tcry.init256_modm(x)


def sc_get64(x):
    """
    Returns 64bit value from the sc
    :param x:
    :return:
    """
    return tcry.get256_modm(x)


def sc_check(key):
    """
    sc_check is not relevant for long-integer scalar representation.

    :param key:
    :return:
    """
    tcry.check256_modm(key)
    return 0


def check_sc(key):
    """
    throws exception on invalid key
    :param key:
    :return:
    """
    if sc_check(key) != 0:
        raise ValueError("Invalid scalar value")


def sc_reduce32(data):
    """
    Exactly the same as sc_reduce (which is default lib sodium)
    except it is assumed that your input s is alread in the form:
    s[0]+256*s[1]+...+256^31*s[31] = s

    And the rest is reducing mod l,
    so basically take a 32 byte input, and reduce modulo the prime.
    :param data:
    :return:
    """
    return tcry.reduce256_modm(data)


def sc_add(aa, bb):
    """
    Scalar addition
    :param aa:
    :param bb:
    :return:
    """
    return tcry.add256_modm(aa, bb)


def sc_sub(aa, bb):
    """
    Scalar subtraction
    :param aa:
    :param bb:
    :return:
    """
    return tcry.sub256_modm(aa, bb)


def sc_isnonzero(c):
    """
    Returns true if scalar is non-zero
    :param c:
    :return:
    """
    return not tcry.iszero256_modm(c)


def sc_eq(a, b):
    """
    Returns true if scalars are equal
    :param a:
    :param b:
    :return:
    """
    return tcry.eq256_modm(a, b)


def sc_mulsub(aa, bb, cc):
    """
    (cc - aa * bb) % l
    :param aa:
    :param bb:
    :param cc:
    :return:
    """
    return tcry.mulsub256_modm(aa, bb, cc)


def random_scalar():
    return tcry.xmr_random_scalar()


#
# GE - ed25519 group
#


def ge_scalarmult(a, A):
    check_ed25519point(A)
    return scalarmult(A, a)


def ge_mul8(P):
    check_ed25519point(P)
    return tcry.ge25519_mul8(P)


def ge_scalarmult_base(a):
    a = sc_reduce32(a)
    return scalarmult_base(a)


def ge_double_scalarmult_base_vartime(a, A, b):
    """
    void ge25519_double_scalarmult_vartime(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const bignum256modm s2);
    r = a * A + b * B
        where a = a[0]+256*a[1]+...+256^31 a[31].
        and b = b[0]+256*b[1]+...+256^31 b[31].
        B is the Ed25519 base point (x,4/5) with x positive.

    :param a:
    :param A:
    :param b:
    :return:
    """
    R = tcry.ge25519_double_scalarmult_vartime(A, a, b)
    tcry.ge25519_norm(R, R)
    return R


def ge_double_scalarmult_base_vartime2(a, A, b, B):
    """
    void ge25519_double_scalarmult_vartime2(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const ge25519 *p2, const bignum256modm s2);
    r = a * A + b * B

    :param a:
    :param A:
    :param b:
    :param B:
    :return:
    """
    R = tcry.ge25519_double_scalarmult_vartime2(A, a, B, b)
    tcry.ge25519_norm(R, R)
    return R


def ge_double_scalarmult_precomp_vartime(a, A, b, Bi):
    """
    void ge_double_scalarmult_precomp_vartime(ge_p2 *r, const unsigned char *a, const ge_p3 *A, const unsigned char *b, const ge_dsmp Bi)
    :return:
    """
    return ge_double_scalarmult_precomp_vartime2(a, A, b, Bi)


def ge_double_scalarmult_precomp_vartime2(a, Ai, b, Bi):
    """
    void ge_double_scalarmult_precomp_vartime2(ge_p2 *r, const unsigned char *a, const ge_dsmp Ai, const unsigned char *b, const ge_dsmp Bi)
    :param a:
    :param Ai:
    :param b:
    :param Bi:
    :return:
    """
    return tcry.xmr_add_keys3(a, Ai, b, Bi)


def identity(byte_enc=False):
    """
    Identity point
    :return:
    """
    idd = tcry.ge25519_set_neutral()
    return idd if not byte_enc else encodepoint(idd)


def ge_frombytes_vartime_check(point):
    """
    https://www.imperialviolet.org/2013/12/25/elligator.html
    http://elligator.cr.yp.to/
    http://elligator.cr.yp.to/elligator-20130828.pdf

    Basically it takes some bytes of data
    converts to a point on the edwards curve
    if the bytes aren't on the curve
    also does some checking on the numbers
    ex. your secret key has to be at least >= 4294967277
    also it rejects certain curve points, i.e. "if x = 0, sign must be positive"

    sqrt(s) = s^((q+3) / 8) if s^((q+3)/4) == s
            = sqrt(-1) s ^((q+3) / 8) otherwise

    :param point:
    :return:
    """
    # if tcry.ge25519_check(point) != 1:
    #     raise ValueError('Point check failed')
    #
    # return 0
    tcry.ge25519_check(point)
    return 0


def ge_frombytes_vartime(point):
    """
    https://www.imperialviolet.org/2013/12/25/elligator.html

    :param point:
    :return:
    """
    ge_frombytes_vartime_check(point)
    return point


def precomp(point):
    """
    Precomputation placeholder
    :param point:
    :return:
    """
    return point


def ge_dsm_precomp(point):
    """
    void ge_dsm_precomp(ge_dsmp r, const ge_p3 *s)
    :param point:
    :return:
    """
    return point


#
# Monero specific
#


def cn_fast_hash(buff):
    """
    Keccak 256, original one (before changes made in SHA3 standard)
    :param buff:
    :return:
    """
    return keccak_hash(buff)


def hash_to_scalar(data, length=None):
    """
    H_s(P)
    :param data:
    :param length:
    :return:
    """
    dt = data[:length] if length else data
    return tcry.xmr_hash_to_scalar(bytes(dt))


def hash_to_ec(buf):
    """
    H_p(buf)

    Code adapted from MiniNero: https://github.com/monero-project/mininero
    https://github.com/monero-project/research-lab/blob/master/whitepaper/ge_fromfe_writeup/ge_fromfe.pdf
    http://archive.is/yfINb
    :param buf:
    :return:
    """
    return tcry.xmr_hash_to_ec(buf)


#
# XMR
#


def gen_H():
    """
    Returns point H
    8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94
    :return:
    """
    return tcry.ge25519_set_h()


def scalarmult_h(i):
    return scalarmult(gen_H(), sc_init(i) if isinstance(i, int) else i)


def add_keys2(a, b, B):
    """
    aG + bB, G is basepoint
    :param a:
    :param b:
    :param B:
    :return:
    """
    return tcry.xmr_add_keys2_vartime(a, b, B)


def add_keys3(a, A, b, B):
    """
    aA + bB
    :param a:
    :param A:
    :param b:
    :param B:
    :return:
    """
    return tcry.xmr_add_keys3_vartime(a, A, b, B)


def gen_c(a, amount):
    """
    Generates Pedersen commitment
    C = aG + bH

    :param a:
    :param amount:
    :return:
    """
    return tcry.xmr_gen_c(a, amount)


def generate_key_derivation(key1, key2):
    """
    Key derivation: 8*(key2*key1)

    :param key1: public key of receiver Bob (see page 7)
    :param key2: Alice's private
    :return:
    """
    if sc_check(key2) != 0:
        # checks that the secret key is uniform enough...
        raise ValueError("error in sc_check in keyder")
    if ge_frombytes_vartime_check(key1) != 0:
        raise ValueError("didn't pass curve checks in keyder")

    return tcry.xmr_generate_key_derivation(key1, key2)


def derivation_to_scalar(derivation, output_index):
    """
    H_s(derivation || varint(output_index))
    :param derivation:
    :param output_index:
    :return:
    """
    check_ed25519point(derivation)
    return tcry.xmr_derivation_to_scalar(derivation, output_index)


def derive_public_key(derivation, output_index, base):
    """
    H_s(derivation || varint(output_index))G + base

    :param derivation:
    :param output_index:
    :param base:
    :return:
    """
    if ge_frombytes_vartime_check(base) != 0:  # check some conditions on the point
        raise ValueError("derive pub key bad point")
    check_ed25519point(base)

    return tcry.xmr_derive_public_key(derivation, output_index, base)


def derive_secret_key(derivation, output_index, base):
    """
    base + H_s(derivation || varint(output_index))
    :param derivation:
    :param output_index:
    :param base:
    :return:
    """
    if sc_check(base) != 0:
        raise ValueError("cs_check in derive_secret_key")
    return tcry.xmr_derive_private_key(derivation, output_index, base)


def prove_range(amount, last_mask=None, *args, **kwargs):
    """
    Range proof provided by the backend. Implemented in C for speed.

    :param amount:
    :param last_mask:
    :return:
    """
    C, a, R = tcry.gen_range_proof(amount, last_mask, *args, **kwargs)

    # Trezor micropython extmod returns byte-serialized/flattened rsig
    return C, a, R


def b16_to_scalar(bts):
    """
    Converts hexcoded bytearray to the scalar
    :param bts:
    :return:
    """
    return decodeint(binascii.unhexlify(bts))


#
# Repr invariant
#


def hmac_point(key, point):
    """
    HMAC single point
    :param key:
    :param point:
    :return:
    """
    return compute_hmac(key, encodepoint(point))


def generate_signature(data, priv):
    """
    Generate EC signature
    crypto_ops::generate_signature(const hash &prefix_hash, const public_key &pub, const secret_key &sec, signature &sig)

    :param data:
    :param priv:
    :return:
    """
    pub = scalarmult_base(priv)

    k = random_scalar()
    comm = scalarmult_base(k)

    buff = data + encodepoint(pub) + encodepoint(comm)
    c = hash_to_scalar(buff)
    r = sc_mulsub(priv, c, k)
    return c, r, pub


def check_signature(data, c, r, pub):
    """
    EC signature verification

    :param data:
    :param pub:
    :param c:
    :param r:
    :return:
    """
    check_ed25519point(pub)
    c = sc_reduce32(c)
    r = sc_reduce32(r)
    if sc_check(c) != 0 or sc_check(r) != 0:
        raise ValueError("Signature error")

    tmp2 = point_add(scalarmult(pub, c), scalarmult_base(r))
    buff = data + encodepoint(pub) + encodepoint(tmp2)
    tmp_c = hash_to_scalar(buff)
    res = sc_sub(tmp_c, c)
    return not sc_isnonzero(res)
