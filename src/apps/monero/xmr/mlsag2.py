#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: https://github.com/monero-project/mininero
# Author: Dusan Klinec, ph4r05, 2018
# see https://eprint.iacr.org/2015/1098.pdf

from apps.monero.xmr import crypto


def key_zero_vector(rows):
    """
    Empty key vector
    :param rows:
    :return:
    """
    vct = []
    for i in range(rows):
        vct.append(crypto.sc_0())
    return vct


def key_vector(rows):
    """
    Empty key vector
    :param rows:
    :return:
    """
    return [None] * rows


def key_matrix(rows, cols):
    """
    first index is columns (so slightly backward from math)
    :param rows:
    :param cols:
    :return:
    """
    rv = [None] * cols
    for i in range(0, cols):
        rv[i] = key_vector(rows)
    return rv


def hash_key_vector(v):
    """
    Hashes key vector
    :param v:
    :return:
    """
    return [crypto.hash_to_ec(vi) for vi in v]


def key_image_vector(x):
    """
    Takes as input a keyvector, returns the keyimage-vector
    TODO: use crypto for generating key images
    :param x:
    :return:
    """
    return [
        crypto.scalarmult(crypto.hash_to_ec(crypto.scalarmult_base(xx)), xx) for xx in x
    ]


def scalar_gen_vector(n):
    """
    Generates vector of scalars
    :param n:
    :return:
    """
    return [crypto.random_scalar() for i in range(0, n)]


#
# Optimized versions with incremental hashing,
# Simple and full variants for Monero
#


def hasher_message(message):
    """
    Returns incremental hasher for MLSAG
    :param message:
    :return:
    """
    from apps.monero.xmr.sub.keccak_hasher import HashWrapper

    ctx = HashWrapper(crypto.get_keccak())
    ctx.update(message)
    ctx.zbuff = bytearray(32)
    return ctx


def hash_point(hasher, point):
    crypto.encodepoint_into(point, hasher.zbuff)
    hasher.update(hasher.zbuff)


def gen_mlsag_assert(pk, xx, kLRki, mscout, index, dsRows):
    """
    Conditions check for gen_mlsag_ext.
    :param pk:
    :param xx:
    :param kLRki:
    :param mscout:
    :param index:
    :param dsRows:
    :return:
    """
    cols = len(pk)
    if cols <= 1:
        raise ValueError("Cols == 1")
    if index >= cols:
        raise ValueError("Index out of range")

    rows = len(pk[0])
    if rows == 0:
        raise ValueError("Empty pk")

    for i in range(cols):
        if len(pk[i]) != rows:
            raise ValueError("pk is not rectangular")
    if len(xx) != rows:
        raise ValueError("Bad xx size")
    if dsRows > rows:
        raise ValueError("Bad dsRows size")
    if (not kLRki or not mscout) and (kLRki or mscout):
        raise ValueError("Only one of kLRki/mscout is present")
    if kLRki and dsRows != 1:
        raise ValueError("Multisig requires exactly 1 dsRows")
    return rows, cols


def gen_mlsag_rows(message, rv, pk, xx, kLRki, index, dsRows, rows, cols):
    """
    MLSAG computation - the part with secret keys
    :param message:
    :param rv:
    :param pk:
    :param xx:
    :param kLRki:
    :param index:
    :param dsRows:
    :param rows:
    :param cols:
    :return:
    """
    Ip = key_vector(dsRows)
    rv.II = key_vector(dsRows)
    alpha = key_vector(rows)
    rv.ss = key_matrix(rows, cols)

    hasher = hasher_message(message)

    for i in range(dsRows):
        hasher.update(crypto.encodepoint(pk[index][i]))
        if kLRki:
            alpha[i] = kLRki.k
            rv.II[i] = kLRki.ki
            hash_point(hasher, kLRki.L)
            hash_point(hasher, kLRki.R)

        else:
            Hi = crypto.hash_to_ec(
                crypto.encodepoint(pk[index][i])
            )  # originally hashToPoint()
            alpha[i] = crypto.random_scalar()
            aGi = crypto.scalarmult_base(alpha[i])
            aHPi = crypto.scalarmult(Hi, alpha[i])
            rv.II[i] = crypto.scalarmult(Hi, xx[i])
            hash_point(hasher, aGi)
            hash_point(hasher, aHPi)

        Ip[i] = crypto.precomp(rv.II[i])

    for i in range(dsRows, rows):
        alpha[i] = crypto.random_scalar()
        aGi = crypto.scalarmult_base(alpha[i])
        hash_point(hasher, pk[index][i])
        hash_point(hasher, aGi)

    c_old = hasher.digest()
    c_old = crypto.sc_reduce32(crypto.decodeint(c_old))
    return c_old, Ip, alpha


def gen_mlsag_ext(message, pk, xx, kLRki, mscout, index, dsRows):
    """
    Multilayered Spontaneous Anonymous Group Signatures (MLSAG signatures)

    :param message:
    :param pk: matrix of points, point form (not encoded)
    :param xx:
    :param kLRki:
    :param mscout:
    :param index:
    :param dsRows:
    :return:
    """
    from apps.monero.xmr.serialize_messages.tx_full import MgSig

    rows, cols = gen_mlsag_assert(pk, xx, kLRki, mscout, index, dsRows)

    rv = MgSig()
    c, L, R, Hi = 0, None, None, None

    c_old, Ip, alpha = gen_mlsag_rows(
        message, rv, pk, xx, kLRki, index, dsRows, rows, cols
    )

    i = (index + 1) % cols
    if i == 0:
        rv.cc = c_old

    while i != index:
        rv.ss[i] = scalar_gen_vector(rows)
        hasher = hasher_message(message)

        for j in range(dsRows):
            L = crypto.add_keys2(rv.ss[i][j], c_old, pk[i][j])
            Hi = crypto.hash_to_ec(
                crypto.encodepoint(pk[i][j])
            )  # originally hashToPoint()
            R = crypto.add_keys3(rv.ss[i][j], Hi, c_old, Ip[j])
            hash_point(hasher, pk[i][j])
            hash_point(hasher, L)
            hash_point(hasher, R)

        for j in range(dsRows, rows):
            L = crypto.add_keys2(rv.ss[i][j], c_old, pk[i][j])
            hash_point(hasher, pk[i][j])
            hash_point(hasher, L)

        c = crypto.sc_reduce32(crypto.decodeint(hasher.digest()))
        c_old = c
        i = (i + 1) % cols

        if i == 0:
            rv.cc = c_old

    for j in range(rows):
        rv.ss[index][j] = crypto.sc_mulsub(
            c, xx[j], alpha[j]
        )  # alpha[j] - c * xx[j]; sc_mulsub in original does c-ab

    if mscout:
        mscout(c)

    return rv, c


def prove_rct_mg(
    message, pubs, in_sk, out_sk, out_pk, kLRki, mscout, index, txn_fee_key
):
    """
    c.f. http://eprint.iacr.org/2015/1098 section 4. definition 10.
    This does the MG sig on the "dest" part of the given key matrix, and
    the last row is the sum of input commitments from that column - sum output commitments
    this shows that sum inputs = sum outputs
    :param message:
    :param pubs: matrix of CtKeys. points are encoded.
    :param in_sk:
    :param out_sk:
    :param out_pk:
    :param kLRki:
    :param mscout:
    :param index:
    :param txn_fee_key:
    :return:
    """
    cols = len(pubs)
    if cols == 0:
        raise ValueError("Empty pubs")
    rows = len(pubs[0])
    if rows == 0:
        raise ValueError("Empty pub row")
    for i in range(cols):
        if len(pubs[i]) != rows:
            raise ValueError("pub is not rectangular")

    if len(in_sk) != rows:
        raise ValueError("Bad inSk size")
    if len(out_sk) != len(out_pk):
        raise ValueError("Bad outsk/putpk size")
    if (not kLRki or not mscout) and (kLRki and mscout):
        raise ValueError("Only one of kLRki/mscout is present")

    sk = key_vector(rows + 1)
    M = key_matrix(rows + 1, cols)
    for i in range(rows + 1):
        sk[i] = crypto.sc_0()

    for i in range(cols):
        M[i][rows] = crypto.identity()
        for j in range(rows):
            M[i][j] = crypto.decodepoint(pubs[i][j].dest)
            M[i][rows] = crypto.point_add(
                M[i][rows], crypto.decodepoint(pubs[i][j].mask)
            )

    sk[rows] = crypto.sc_0()
    for j in range(rows):
        sk[j] = in_sk[j].dest
        sk[rows] = crypto.sc_add(sk[rows], in_sk[j].mask)  # add masks in last row

    for i in range(cols):
        for j in range(len(out_pk)):
            M[i][rows] = crypto.point_sub(
                M[i][rows], crypto.decodepoint(out_pk[j].mask)
            )  # subtract output Ci's in last row

        # Subtract txn fee output in last row
        M[i][rows] = crypto.point_sub(M[i][rows], txn_fee_key)

    for j in range(len(out_pk)):
        sk[rows] = crypto.sc_sub(
            sk[rows], out_sk[j].mask
        )  # subtract output masks in last row

    return gen_mlsag_ext(message, M, sk, kLRki, mscout, index, rows)


def prove_rct_mg_simple(message, pubs, in_sk, a, cout, kLRki, mscout, index):
    """
    Simple version for when we assume only
        post rct inputs
        here pubs is a vector of (P, C) length mixin

    :param message:
    :param pubs: vector of CtKeys, public, point values, encoded form. (dest, mask) = (P, C)
    :param in_sk: CtKey, private. (spending private key, input commitment mask (original))
    :param a: mask from the pseudo_output commitment (alpha)
    :param cout: point, decoded. Pseudo output public key.
    :param kLRki:
    :param mscout: lambda accepting c
    :param index:
    :return:
    """
    rows = 1
    cols = len(pubs)
    if cols == 0:
        raise ValueError("Empty pubs")
    if (not kLRki or not mscout) and (kLRki and mscout):
        raise ValueError("Only one of kLRki/mscout is present")

    sk = key_vector(rows + 1)
    M = key_matrix(rows + 1, cols)

    sk[0] = in_sk.dest
    sk[1] = crypto.sc_sub(in_sk.mask, a)

    for i in range(cols):
        M[i][0] = crypto.decodepoint(pubs[i].dest)
        M[i][1] = crypto.point_sub(crypto.decodepoint(pubs[i].mask), cout)

    return gen_mlsag_ext(message, M, sk, kLRki, mscout, index, rows)
