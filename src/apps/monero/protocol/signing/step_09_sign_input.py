"""
Generates a signature for one input.
"""

import gc

from .state import State

from apps.monero.controller import misc
from apps.monero.layout import confirms
from apps.monero.xmr import common, crypto

if False:
    from trezor.messages.MoneroTransactionSourceEntry import (
        MoneroTransactionSourceEntry,
    )


async def sign_input(
    state: State,
    src_entr: MoneroTransactionSourceEntry,
    vini_bin: bytes,
    vini_hmac: bytes,
    pseudo_out: bytes,
    pseudo_out_hmac: bytes,
    pseudo_out_alpha_enc: bytes,
    spend_enc: bytes,
):
    """
    :param state: transaction state
    :param src_entr: Source entry
    :param vini_bin: tx.vin[i] for the transaction. Contains key image, offsets, amount (usually zero)
    :param vini_hmac: HMAC for the tx.vin[i] as returned from Trezor
    :param pseudo_out: Pedersen commitment for the current input, uses pseudo_out_alpha
                       as a mask. Only applicable for RCTTypeSimple.
    :param pseudo_out_hmac: HMAC for pseudo_out
    :param pseudo_out_alpha_enc: alpha mask used in pseudo_out, only applicable for RCTTypeSimple. Encrypted.
    :param spend_enc: one time address spending private key. Encrypted.
    :return: Generated signature MGs[i]
    """
    from apps.monero.protocol import hmac_encryption_keys

    await confirms.transaction_step(
        state.ctx, state.STEP_SIGN, state.current_input_index + 1, state.input_count
    )

    state.current_input_index += 1
    if state.current_input_index >= state.input_count:
        raise ValueError("Invalid inputs count")
    if state.use_simple_rct and pseudo_out is None:
        raise ValueError("SimpleRCT requires pseudo_out but none provided")
    if state.use_simple_rct and pseudo_out_alpha_enc is None:
        raise ValueError("SimpleRCT requires pseudo_out's mask but none provided")
    if state.current_input_index >= 1 and not state.use_simple_rct:
        raise ValueError("Two and more inputs must imply SimpleRCT")

    input_position = state.source_permutation[state.current_input_index]

    # Check input's HMAC
    vini_hmac_comp = await hmac_encryption_keys.gen_hmac_vini(
        state.key_hmac, src_entr, vini_bin, input_position
    )
    if not common.ct_equal(vini_hmac_comp, vini_hmac):
        raise ValueError("HMAC is not correct")

    gc.collect()
    state.mem_trace(1)

    if state.use_simple_rct:
        # both pseudo_out and its mask were offloaded so we need to
        # validate pseudo_out's HMAC and decrypt the alpha
        pseudo_out_hmac_comp = crypto.compute_hmac(
            hmac_encryption_keys.hmac_key_txin_comm(state.key_hmac, input_position),
            pseudo_out,
        )
        if not common.ct_equal(pseudo_out_hmac_comp, pseudo_out_hmac):
            raise ValueError("HMAC is not correct")

        gc.collect()
        state.mem_trace(2)

        from apps.monero.xmr.enc import chacha_poly

        pseudo_out_alpha = crypto.decodeint(
            chacha_poly.decrypt_pack(
                hmac_encryption_keys.enc_key_txin_alpha(state.key_enc, input_position),
                bytes(pseudo_out_alpha_enc),
            )
        )
        pseudo_out_c = crypto.decodepoint(pseudo_out)

    # Spending secret
    from apps.monero.xmr.enc import chacha_poly
    from apps.monero.xmr.serialize_messages.ct_keys import CtKey

    spend_key = crypto.decodeint(
        chacha_poly.decrypt_pack(
            hmac_encryption_keys.enc_key_spend(state.key_enc, input_position),
            bytes(spend_enc),
        )
    )

    gc.collect()
    state.mem_trace(3)

    # Basic setup, sanity check
    index = src_entr.real_output
    input_secret_key = CtKey(dest=spend_key, mask=crypto.decodeint(src_entr.mask))
    kLRki = None  # for multisig: src_entr.multisig_kLRki

    # Private key correctness test
    state.assrt(
        crypto.point_eq(
            crypto.decodepoint(src_entr.outputs[src_entr.real_output].key.dest),
            crypto.scalarmult_base(input_secret_key.dest),
        ),
        "Real source entry's destination does not equal spend key's",
    )
    state.assrt(
        crypto.point_eq(
            crypto.decodepoint(src_entr.outputs[src_entr.real_output].key.mask),
            crypto.gen_commitment(input_secret_key.mask, src_entr.amount),
        ),
        "Real source entry's mask does not equal spend key's",
    )

    gc.collect()
    state.mem_trace(4)

    # RCT signature
    from apps.monero.xmr import mlsag2

    if state.use_simple_rct:
        # Simple RingCT
        mix_ring = [x.key for x in src_entr.outputs]
        mg, msc = mlsag2.prove_rct_mg_simple(
            state.full_message,
            mix_ring,
            input_secret_key,
            pseudo_out_alpha,
            pseudo_out_c,
            kLRki,
            index,
        )

    else:
        # Full RingCt, only one input
        txn_fee_key = crypto.scalarmult_h(state.fee)
        mix_ring = [[x.key] for x in src_entr.outputs]

        mg, msc = mlsag2.prove_rct_mg(
            state.full_message,
            mix_ring,
            [input_secret_key],
            state.output_sk_masks,
            state.output_pk_masks,
            kLRki,
            index,
            txn_fee_key,
        )

    gc.collect()
    state.mem_trace(5)

    # Encode
    mgs = _recode_msg([mg])
    cout = None

    gc.collect()
    state.mem_trace(6)

    from trezor.messages.MoneroTransactionSignInputAck import (
        MoneroTransactionSignInputAck,
    )

    return MoneroTransactionSignInputAck(
        signature=misc.dump_msg_gc(mgs[0], preallocate=488), cout=cout
    )


def _recode_msg(mgs):
    """
    Recodes MGs signatures from raw forms to bytearrays so it works with serialization
    """
    for idx in range(len(mgs)):
        mgs[idx].cc = crypto.encodeint(mgs[idx].cc)
        if hasattr(mgs[idx], "II") and mgs[idx].II:
            for i in range(len(mgs[idx].II)):
                mgs[idx].II[i] = crypto.encodepoint(mgs[idx].II[i])

        for i in range(len(mgs[idx].ss)):
            for j in range(len(mgs[idx].ss[i])):
                mgs[idx].ss[i][j] = crypto.encodeint(mgs[idx].ss[i][j])
    return mgs
