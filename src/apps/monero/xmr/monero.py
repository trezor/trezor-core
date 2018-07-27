#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import ustruct as struct
from micropython import const

from apps.monero.xmr import common, crypto

DISPLAY_DECIMAL_POINT = const(12)


class XmrNoSuchAddressException(common.XmrException):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


def get_subaddress_secret_key(
    secret_key, index=None, major=None, minor=None, little_endian=True
):
    """
    Builds subaddress secret key from the subaddress index
    Hs(SubAddr || a || index_major || index_minor)

    UPDATE: Monero team fixed this problem. Always use little endian.
    Note: need to handle endianity in the index
    C-code simply does: memcpy(data + sizeof(prefix) + sizeof(crypto::secret_key), &index, sizeof(subaddress_index));
    Where the index has the following form:

    struct subaddress_index {
        uint32_t major;
        uint32_t minor;
    }

    https://docs.python.org/3/library/struct.html#byte-order-size-and-alignment
    :param secret_key:
    :param index:
    :param major:
    :param minor:
    :param little_endian:
    :return:
    """
    if index:
        major = index.major
        minor = index.minor
    endianity = "<" if little_endian else ">"
    prefix = b"SubAddr"
    buffer = bytearray(len(prefix) + 1 + 32 + 4 + 4)
    struct.pack_into(
        "%s7sb32sLL" % endianity,
        buffer,
        0,
        prefix,
        0,
        crypto.encodeint(secret_key),
        major,
        minor,
    )
    return crypto.hash_to_scalar(buffer)


def get_subaddress_spend_public_key(view_private, spend_public, major, minor):
    """
    Generates subaddress spend public key D_{major, minor}
    :param view_private:
    :param spend_public:
    :param major:
    :param minor:
    :return:
    """
    m = get_subaddress_secret_key(view_private, major=major, minor=minor)
    M = crypto.scalarmult_base(m)
    D = crypto.point_add(spend_public, M)
    return D


def generate_key_derivation(pub_key, priv_key):
    """
    Generates derivation priv_key * pub_key.
    Simple ECDH.
    :param pub_key:
    :param priv_key:
    :return:
    """
    return crypto.generate_key_derivation(pub_key, priv_key)


def derive_subaddress_public_key(out_key, derivation, output_index):
    """
    out_key - H_s(derivation || varint(output_index))G
    :param out_key:
    :param derivation:
    :param output_index:
    :return:
    """
    crypto.check_ed25519point(out_key)
    scalar = crypto.derivation_to_scalar(derivation, output_index)
    point2 = crypto.scalarmult_base(scalar)
    point4 = crypto.point_sub(out_key, point2)
    return point4


def generate_key_image(public_key, secret_key):
    """
    Key image: secret_key * H_p(pub_key)
    :param public_key: encoded point
    :param secret_key:
    :return:
    """
    point = crypto.hash_to_ec(public_key)
    point2 = crypto.ge_scalarmult(secret_key, point)
    return point2


def is_out_to_acc_precomp(
    subaddresses, out_key, derivation, additional_derivations, output_index
):
    """
    Searches subaddresses for the computed subaddress_spendkey.
    If found, returns (major, minor), derivation.

    :param subaddresses:
    :param out_key:
    :param derivation:
    :param additional_derivations:
    :param output_index:
    :return:
    """
    subaddress_spendkey = crypto.encodepoint(
        derive_subaddress_public_key(out_key, derivation, output_index)
    )
    if subaddress_spendkey in subaddresses:
        return subaddresses[subaddress_spendkey], derivation

    if additional_derivations and len(additional_derivations) > 0:
        if output_index >= len(additional_derivations):
            raise ValueError("Wrong number of additional derivations")

        subaddress_spendkey = derive_subaddress_public_key(
            out_key, additional_derivations[output_index], output_index
        )
        subaddress_spendkey = crypto.encodepoint(subaddress_spendkey)
        if subaddress_spendkey in subaddresses:
            return (
                subaddresses[subaddress_spendkey],
                additional_derivations[output_index],
            )

    return None


def generate_key_image_helper_precomp(
    ack, out_key, recv_derivation, real_output_index, received_index
):
    """
    Generates UTXO spending key and key image.

    :param ack: sender credentials
    :type ack: apps.monero.xmr.sub.creds.AccountCreds
    :param out_key: real output (from input RCT) destination key
    :param recv_derivation:
    :param real_output_index:
    :param received_index: subaddress index this payment was received to
    :return:
    """
    if ack.spend_key_private == 0:
        raise ValueError("Watch-only wallet not supported")

    # derive secret key with subaddress - step 1: original CN derivation
    scalar_step1 = crypto.derive_secret_key(
        recv_derivation, real_output_index, ack.spend_key_private
    )

    # step 2: add Hs(SubAddr || a || index_major || index_minor)
    subaddr_sk = None
    scalar_step2 = None
    if received_index == (0, 0):
        scalar_step2 = scalar_step1
    else:
        subaddr_sk = get_subaddress_secret_key(
            ack.view_key_private, major=received_index[0], minor=received_index[1]
        )
        scalar_step2 = crypto.sc_add(scalar_step1, subaddr_sk)

    # when not in multisig, we know the full spend secret key, so the output pubkey can be obtained by scalarmultBase
    if len(ack.multisig_keys) == 0:
        pub_ver = crypto.scalarmult_base(scalar_step2)

    else:
        # When in multisig, we only know the partial spend secret key. But we do know the full spend public key,
        # so the output pubkey can be obtained by using the standard CN key derivation.
        pub_ver = crypto.derive_public_key(
            recv_derivation, real_output_index, ack.spend_key_public
        )

        # Add the contribution from the subaddress part
        if received_index != (0, 0):
            subaddr_pk = crypto.scalarmult_base(subaddr_sk)
            pub_ver = crypto.point_add(pub_ver, subaddr_pk)

    if not crypto.point_eq(pub_ver, out_key):
        raise ValueError(
            "key image helper precomp: given output pubkey doesn't match the derived one"
        )

    ki = generate_key_image(crypto.encodepoint(pub_ver), scalar_step2)
    return scalar_step2, ki


def generate_key_image_helper(
    creds,
    subaddresses,
    out_key,
    tx_public_key,
    additional_tx_public_keys,
    real_output_index,
):
    """
    Generates UTXO spending key and key image.
    Supports subaddresses.

    :param creds:
    :param subaddresses:
    :param out_key: real output (from input RCT) destination key
    :param tx_public_key: real output (from input RCT) public key
    :param additional_tx_public_keys:
    :param real_output_index: index of the real output in the RCT
    :return:
    """
    recv_derivation = generate_key_derivation(tx_public_key, creds.view_key_private)

    additional_recv_derivations = []
    for add_pub_key in additional_tx_public_keys:
        additional_recv_derivations.append(
            generate_key_derivation(add_pub_key, creds.view_key_private)
        )

    subaddr_recv_info = is_out_to_acc_precomp(
        subaddresses,
        out_key,
        recv_derivation,
        additional_recv_derivations,
        real_output_index,
    )
    if subaddr_recv_info is None:
        raise XmrNoSuchAddressException("No such addr")

    xi, ki = generate_key_image_helper_precomp(
        creds, out_key, subaddr_recv_info[1], real_output_index, subaddr_recv_info[0]
    )
    return xi, ki, recv_derivation


def compute_subaddresses(creds, account, indices, subaddresses=None):
    """
    Computes subaddress public spend key for receiving transactions.

    :param creds: credentials
    :param account: major index
    :param indices: array of minor indices
    :param subaddresses: subaddress dict. optional.
    :return:
    """
    if subaddresses is None:
        subaddresses = {}

    for idx in indices:
        if account == 0 and idx == 0:
            subaddresses[crypto.encodepoint(creds.spend_key_public)] = (0, 0)
            continue

        pub = get_subaddress_spend_public_key(
            creds.view_key_private, creds.spend_key_public, major=account, minor=idx
        )
        pub = crypto.encodepoint(pub)
        subaddresses[pub] = (account, idx)
    return subaddresses


def generate_keys(recovery_key):
    """
    Wallet gen.
    :param recovery_key:
    :return:
    """
    sec = crypto.sc_reduce32(recovery_key)
    pub = crypto.scalarmult_base(sec)
    return sec, pub


def generate_monero_keys(seed):
    """
    Generates spend key / view key from the seed in the same manner as Monero code does.

    account.cpp:
    crypto::secret_key account_base::generate(const crypto::secret_key& recovery_key, bool recover, bool two_random).
    :param seed:
    :return:
    """
    spend_sec, spend_pub = generate_keys(crypto.decodeint(seed))
    hash = crypto.cn_fast_hash(crypto.encodeint(spend_sec))
    view_sec, view_pub = generate_keys(crypto.decodeint(hash))
    return spend_sec, spend_pub, view_sec, view_pub
