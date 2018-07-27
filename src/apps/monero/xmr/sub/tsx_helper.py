#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018
from apps.monero.xmr import crypto
from apps.monero.xmr.serialize import xmrserialize
from apps.monero.xmr.serialize.readwriter import MemoryReaderWriter
from apps.monero.xmr.serialize_messages.addr import AccountPublicAddress
from apps.monero.xmr.serialize_messages.tx_extra import (
    TxExtraAdditionalPubKeys,
    TxExtraField,
)


async def parse_extra_fields(extra_buff):
    """
    Parses extra buffer to the extra fields vector
    :param extra_buff:
    :return:
    """
    extras = []
    rw = MemoryReaderWriter(extra_buff)
    ar2 = xmrserialize.Archive(rw, False)
    while len(rw.get_buffer()) > 0:
        extras.append(await ar2.variant(elem_type=TxExtraField))
    return extras


def find_tx_extra_field_by_type(extra_fields, msg, idx=0):
    """
    Finds given message type in the extra array, or returns None if not found
    :param extra_fields:
    :param msg:
    :param idx:
    :return:
    """
    cur_idx = 0
    for x in extra_fields:
        if isinstance(x, msg):
            if cur_idx == idx:
                return x
            cur_idx += 1
    return None


def has_encrypted_payment_id(extra_nonce):
    """
    Returns true if encrypted payment id is present
    :param extra_nonce:
    :return:
    """
    return len(extra_nonce) == 9 and extra_nonce[0] == 1


def has_payment_id(extra_nonce):
    """
    Returns true if payment id is present
    :param extra_nonce:
    :return:
    """
    return len(extra_nonce) == 33 and extra_nonce[0] == 0


def get_payment_id_from_tx_extra_nonce(extra_nonce):
    """
    Extracts encrypted payment id from extra
    :param extra_nonce:
    :return:
    """
    if 33 != len(extra_nonce):
        raise ValueError("Nonce size mismatch")
    if 0x0 != extra_nonce[0]:
        raise ValueError("Nonce payment type invalid")
    return extra_nonce[1:]


def get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce):
    """
    Extracts encrypted payment id from extra
    :param extra_nonce:
    :return:
    """
    if 9 != len(extra_nonce):
        raise ValueError("Nonce size mismatch")
    if 0x1 != extra_nonce[0]:
        raise ValueError("Nonce payment type invalid")
    return extra_nonce[1:]


def set_payment_id_to_tx_extra_nonce(payment_id):
    """
    Sets payment ID to the extra
    :param payment_id:
    :return:
    """
    return b"\x00" + payment_id


def absolute_output_offsets_to_relative(off):
    """
    Relative offsets, prev + cur = next.
    Helps with varint encoding size.
    :param off:
    :return:
    """
    if len(off) == 0:
        return off
    res = sorted(off)
    for i in range(len(off) - 1, 0, -1):
        res[i] -= res[i - 1]
    return res


def get_destination_view_key_pub(destinations, change_addr=None):
    """
    Returns destination address public view key
    :param destinations:
    :type destinations: list[apps.monero.xmr.serialize_messages.tx_construct.TxDestinationEntry]
    :param change_addr:
    :return:
    """
    from apps.monero.xmr.sub.addr import addr_eq

    addr = AccountPublicAddress(
        m_spend_public_key=crypto.NULL_KEY_ENC, m_view_public_key=crypto.NULL_KEY_ENC
    )
    count = 0
    for dest in destinations:
        if dest.amount == 0:
            continue
        if change_addr and addr_eq(dest.addr, change_addr):
            continue
        if addr_eq(dest.addr, addr):
            continue
        if count > 0:
            return crypto.NULL_KEY_ENC
        addr = dest.addr
        count += 1
    return addr.m_view_public_key


def encrypt_payment_id(payment_id, public_key, secret_key):
    """
    Encrypts payment_id hex.
    Used in the transaction extra. Only recipient is able to decrypt.
    :param payment_id:
    :param public_key:
    :param secret_key:
    :return:
    """
    derivation_p = crypto.generate_key_derivation(public_key, secret_key)
    derivation = bytearray(33)
    derivation = crypto.encodepoint_into(derivation_p, derivation)
    derivation[32] = 0x8b
    hash = crypto.cn_fast_hash(derivation)
    pm_copy = bytearray(payment_id)
    for i in range(8):
        pm_copy[i] ^= hash[i]
    return pm_copy


def set_encrypted_payment_id_to_tx_extra_nonce(payment_id):
    return b"\x01" + payment_id


async def remove_field_from_tx_extra(extra, mtype):
    """
    Removes extra field of fiven type from the buffer
    Reserializes with skipping the given mtype.
    :param extra:
    :param mtype:
    :return:
    """
    if len(extra) == 0:
        return []

    reader = MemoryReaderWriter(extra)
    writer = MemoryReaderWriter()
    ar_read = xmrserialize.Archive(reader, False)
    ar_write = xmrserialize.Archive(writer, True)
    while len(reader.get_buffer()) > 0:
        c_extras = await ar_read.variant(elem_type=TxExtraField)
        if not isinstance(c_extras, mtype):
            await ar_write.variant(c_extras, elem_type=TxExtraField)

    return writer.get_buffer()


def add_extra_nonce_to_tx_extra(extra, extra_nonce):
    """
    Appends nonce extra to the extra buffer
    :param extra:
    :param extra_nonce:
    :return:
    """
    if len(extra_nonce) > 255:
        raise ValueError("Nonce could be 255 bytes max")
    extra += b"\x02" + len(extra_nonce).to_bytes(1, "big") + extra_nonce
    return extra


def add_tx_pub_key_to_extra(tx_extra, pub_key):
    """
    Adds public key to the extra
    :param tx_extra:
    :param pub_key:
    :return:
    """
    to_add = bytearray(33)
    to_add[0] = 1
    crypto.encodepoint_into(pub_key, memoryview(to_add)[1:])  # TX_EXTRA_TAG_PUBKEY
    return tx_extra + to_add


async def add_additional_tx_pub_keys_to_extra(
    tx_extra, additional_pub_keys=None, pub_enc=None
):
    """
    Adds all pubkeys to the extra
    :param tx_extra:
    :param additional_pub_keys:
    :param pub_enc: None
    :return:
    """
    pubs_msg = TxExtraAdditionalPubKeys(
        data=pub_enc
        if pub_enc
        else [crypto.encodepoint(x) for x in additional_pub_keys]
    )

    rw = MemoryReaderWriter()
    ar = xmrserialize.Archive(rw, True)

    # format: variant_tag (0x4) | array len varint | 32B | 32B | ...
    await ar.variant(pubs_msg, TxExtraField)
    tx_extra += bytes(rw.get_buffer())
    return tx_extra
