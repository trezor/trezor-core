#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: https://github.com/monero-project/mininero
# Author: Dusan Klinec, ph4r05, 2018

from apps.monero.xmr import crypto


def prove_range(
    amount, last_mask=None, decode=False, backend_impl=True, byte_enc=True, rsig=None
):
    """
    Range proof generator.
    In order to minimize the memory consumption and CPU usage during transaction generation the returned values
    are returned encoded.

    :param amount:
    :param last_mask:
    :param backend_impl: backend implementation, if available
    :param decode: decodes output
    :param byte_enc: byte encoded
    :param rsig: buffer for rsig
    :return:
    """
    if not backend_impl or not byte_enc or decode:
        raise ValueError("Unsupported params")

    C, a, R = None, None, None
    try:
        if rsig is None:
            rsig = bytearray(32 * (64 + 64 + 64 + 1))

        buf_ai = bytearray(4 * 9 * 64)
        buf_alpha = bytearray(4 * 9 * 64)
        C, a, R = crypto.prove_range(
            rsig, amount, last_mask, buf_ai, buf_alpha
        )  # backend returns encoded

    finally:
        import gc

        buf_ai = None
        buf_alpha = None
        gc.collect()

    return C, a, R


# Ring-ct MG sigs
# Prove:
#   c.f. http:#eprint.iacr.org/2015/1098 section 4. definition 10.
#   This does the MG sig on the "dest" part of the given key matrix, and
#   the last row is the sum of input commitments from that column - sum output commitments
#   this shows that sum inputs = sum outputs
# Ver:
#   verifies the above sig is created corretly


def ecdh_encode(unmasked, receiver_pk=None, derivation=None):
    """
    Elliptic Curve Diffie-Helman: encodes and decodes the amount b and mask a
    where C= aG + bH
    :param unmasked:
    :param receiver_pk:
    :param derivation:
    :return:
    """
    from apps.monero.xmr.serialize_messages.tx_ecdh import EcdhTuple

    rv = EcdhTuple()
    if derivation is None:
        esk = crypto.random_scalar()
        rv.senderPk = crypto.scalarmult_base(esk)
        derivation = crypto.encodepoint(crypto.scalarmult(receiver_pk, esk))

    sharedSec1 = crypto.hash_to_scalar(derivation)
    sharedSec2 = crypto.hash_to_scalar(crypto.encodeint(sharedSec1))

    rv.mask = crypto.sc_add(unmasked.mask, sharedSec1)
    rv.amount = crypto.sc_add(unmasked.amount, sharedSec2)
    return rv


def ecdh_decode(masked, receiver_sk=None, derivation=None):
    """
    Elliptic Curve Diffie-Helman: encodes and decodes the amount b and mask a
    where C= aG + bH
    :param masked:
    :param receiver_sk:
    :param derivation:
    :return:
    """
    from apps.monero.xmr.serialize_messages.tx_ecdh import EcdhTuple

    rv = EcdhTuple()

    if derivation is None:
        derivation = crypto.scalarmult(masked.senderPk, receiver_sk)

    sharedSec1 = crypto.hash_to_scalar(derivation)
    sharedSec2 = crypto.hash_to_scalar(crypto.encodeint(sharedSec1))

    rv.mask = crypto.sc_sub(masked.mask, sharedSec1)
    rv.amount = crypto.sc_sub(masked.amount, sharedSec2)
    return rv


#
# Key image import / export
#


def generate_ring_signature(prefix_hash, image, pubs, sec, sec_idx, test=False):
    """
    Generates ring signature with key image.
    void crypto_ops::generate_ring_signature()

    :param prefix_hash:
    :param image:
    :param pubs:
    :param sec:
    :param sec_idx:
    :param test:
    :return:
    """
    from apps.monero.xmr.common import memcpy

    if test:
        from apps.monero.xmr import monero

        t = crypto.scalarmult_base(sec)
        if not crypto.point_eq(t, pubs[sec_idx]):
            raise ValueError("Invalid sec key")

        k_i = monero.generate_key_image(crypto.encodepoint(pubs[sec_idx]), sec)
        if not crypto.point_eq(k_i, image):
            raise ValueError("Key image invalid")
        for k in pubs:
            crypto.ge_frombytes_vartime_check(k)

    image_unp = crypto.ge_frombytes_vartime(image)
    image_pre = crypto.ge_dsm_precomp(image_unp)

    buff_off = len(prefix_hash)
    buff = bytearray(buff_off + 2 * 32 * len(pubs))
    memcpy(buff, 0, prefix_hash, 0, buff_off)
    mvbuff = memoryview(buff)

    sum = crypto.sc_0()
    k = crypto.sc_0()
    sig = []
    for i in range(len(pubs)):
        sig.append([crypto.sc_0(), crypto.sc_0()])  # c, r

    for i in range(len(pubs)):
        if i == sec_idx:
            k = crypto.random_scalar()
            tmp3 = crypto.scalarmult_base(k)
            crypto.encodepoint_into(tmp3, mvbuff[buff_off : buff_off + 32])
            buff_off += 32

            tmp3 = crypto.hash_to_ec(crypto.encodepoint(pubs[i]))
            tmp2 = crypto.scalarmult(tmp3, k)
            crypto.encodepoint_into(tmp2, mvbuff[buff_off : buff_off + 32])
            buff_off += 32

        else:
            sig[i] = [crypto.random_scalar(), crypto.random_scalar()]
            tmp3 = crypto.ge_frombytes_vartime(pubs[i])
            tmp2 = crypto.ge_double_scalarmult_base_vartime(sig[i][0], tmp3, sig[i][1])
            crypto.encodepoint_into(tmp2, mvbuff[buff_off : buff_off + 32])
            buff_off += 32

            tmp3 = crypto.hash_to_ec(crypto.encodepoint(tmp3))
            tmp2 = crypto.ge_double_scalarmult_precomp_vartime(
                sig[i][1], tmp3, sig[i][0], image_pre
            )
            crypto.encodepoint_into(tmp2, mvbuff[buff_off : buff_off + 32])
            buff_off += 32

            sum = crypto.sc_add(sum, sig[i][0])

    h = crypto.hash_to_scalar(buff)
    sig[sec_idx][0] = crypto.sc_sub(h, sum)
    sig[sec_idx][1] = crypto.sc_mulsub(sig[sec_idx][0], sec, k)
    return sig


def check_ring_singature(prefix_hash, image, pubs, sig):
    """
    Checks ring signature generated with generate_ring_signature
    :param prefix_hash:
    :param image:
    :param pubs:
    :param sig:
    :return:
    """
    from apps.monero.xmr.common import memcpy

    image_unp = crypto.ge_frombytes_vartime(image)
    image_pre = crypto.ge_dsm_precomp(image_unp)

    buff_off = len(prefix_hash)
    buff = bytearray(buff_off + 2 * 32 * len(pubs))
    memcpy(buff, 0, prefix_hash, 0, buff_off)
    mvbuff = memoryview(buff)

    sum = crypto.sc_0()
    for i in range(len(pubs)):
        if crypto.sc_check(sig[i][0]) != 0 or crypto.sc_check(sig[i][1]) != 0:
            return False

        tmp3 = crypto.ge_frombytes_vartime(pubs[i])
        tmp2 = crypto.ge_double_scalarmult_base_vartime(sig[i][0], tmp3, sig[i][1])
        crypto.encodepoint_into(tmp2, mvbuff[buff_off : buff_off + 32])
        buff_off += 32

        tmp3 = crypto.hash_to_ec(crypto.encodepoint(pubs[i]))
        tmp2 = crypto.ge_double_scalarmult_precomp_vartime(
            sig[i][1], tmp3, sig[i][0], image_pre
        )
        crypto.encodepoint_into(tmp2, mvbuff[buff_off : buff_off + 32])
        buff_off += 32

        sum = crypto.sc_add(sum, sig[i][0])

    h = crypto.hash_to_scalar(buff)
    h = crypto.sc_sub(h, sum)
    return crypto.sc_isnonzero(h) == 0


def export_key_image(
    creds,
    subaddresses,
    pkey,
    tx_pub_key,
    additional_tx_pub_keys,
    out_idx,
    test=True,
    verify=True,
):
    """
    Generates key image for the TXO + signature for the key image
    :param creds:
    :param subaddresses:
    :param pkey:
    :param tx_pub_key:
    :param additional_tx_pub_keys:
    :param out_idx:
    :param test:
    :param verify:
    :return:
    """
    from apps.monero.xmr import monero

    r = monero.generate_key_image_helper(
        creds, subaddresses, pkey, tx_pub_key, additional_tx_pub_keys, out_idx
    )
    xi, ki, recv_derivation = r[:3]

    phash = crypto.encodepoint(ki)
    sig = generate_ring_signature(phash, ki, [pkey], xi, 0, test)

    if verify:
        if check_ring_singature(phash, ki, [pkey], sig) != 1:
            raise ValueError("Signature error")

    return ki, sig
