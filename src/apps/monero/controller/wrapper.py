#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


MONERO_CURVE = "secp256k1"  # 'ed25519-keccak'


async def monero_get_creds(ctx, address_n=None, network_type=None):
    from apps.common import seed
    from apps.monero.xmr import crypto
    from apps.monero.xmr import monero
    from apps.monero.xmr.sub.creds import AccountCreds

    address_n = address_n or ()
    node = await seed.derive_node(ctx, address_n, MONERO_CURVE)

    key_seed = crypto.cn_fast_hash(node.private_key())
    keys = monero.generate_monero_keys(
        key_seed
    )  # spend_sec, spend_pub, view_sec, view_pub

    creds = AccountCreds.new_wallet(keys[2], keys[0], network_type)
    return creds


def get_interface(ctx):
    from apps.monero.controller import iface

    return iface.get_iface(ctx)


def exc2str(e):
    return str(e)
