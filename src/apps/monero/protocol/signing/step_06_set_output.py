"""
Output destinations are streamed one by one.
Computes destination one-time address, amount key, range proof + HMAC, out_pk, ecdh_info.
"""
import gc

from trezor import utils

from .state import State

from apps.monero.controller import misc
from apps.monero.layout import confirms
from apps.monero.protocol import hmac_encryption_keys
from apps.monero.xmr import common, crypto


async def set_output(state: State, dst_entr, dst_entr_hmac, rsig_data):
    state.mem_trace(0, True)
    mods = utils.unimport_begin()

    await confirms.transaction_step(
        state.ctx, state.STEP_OUT, state.current_output_index + 1, state.output_count
    )
    state.mem_trace(1)

    state.current_output_index += 1
    state.mem_trace(2, True)
    await _validate(state, dst_entr, dst_entr_hmac)

    # First output - we include the size of the container into the tx prefix hasher
    if state.current_output_index == 0:
        state.tx_prefix_hasher.uvarint(state.output_count)
    state.mem_trace(4, True)

    state.output_amounts.append(dst_entr.amount)
    state.summary_outs_money += dst_entr.amount
    utils.unimport_end(mods)
    state.mem_trace(5, True)

    # Range proof first, memory intensive
    rsig, mask = _range_proof(state, dst_entr.amount, rsig_data)
    utils.unimport_end(mods)
    state.mem_trace(6, True)

    # additional tx key if applicable
    additional_txkey_priv = _set_out_additional_keys(state, dst_entr)
    # derivation = a*R or r*A or s*C
    derivation = _set_out_derivation(state, dst_entr, additional_txkey_priv)
    # amount key = H_s(derivation || i)
    amount_key = crypto.derivation_to_scalar(derivation, state.current_output_index)
    # one-time destination address P = H_s(derivation || i)*G + B
    tx_out_key = crypto.derive_public_key(
        derivation,
        state.current_output_index,
        crypto.decodepoint(dst_entr.addr.spend_public_key),
    )
    del (derivation, additional_txkey_priv)
    state.mem_trace(7, True)

    # Tx header prefix hashing, hmac dst_entr
    tx_out_bin, hmac_vouti = await _set_out_tx_out(state, dst_entr, tx_out_key)
    state.mem_trace(11, True)

    out_pk, ecdh_info_bin = _get_ecdh_info_and_out_pk(
        state=state,
        tx_out_key=tx_out_key,
        amount=dst_entr.amount,
        mask=mask,
        amount_key=amount_key,
    )
    del (dst_entr, mask, amount_key, tx_out_key)
    state.mem_trace(12, True)

    # Incremental hashing of the ECDH info.
    # RctSigBase allows to hash only one of the (ecdh, out_pk) as they are serialized
    # as whole vectors. We choose to hash ECDH first, because it saves state space.
    state.full_message_hasher.set_ecdh(ecdh_info_bin)
    state.mem_trace(13, True)

    # Output_pk is stored to the state as it is used during the signature and hashed to the
    # RctSigBase later. No need to store amount, it was already stored.
    state.output_pk_masks.append(out_pk.mask)
    state.mem_trace(14, True)

    from trezor.messages.MoneroTransactionSetOutputAck import (
        MoneroTransactionSetOutputAck,
    )

    out_pk_bin = bytearray(64)
    utils.memcpy(out_pk_bin, 0, out_pk.dest, 0, 32)
    utils.memcpy(out_pk_bin, 32, out_pk.mask, 0, 32)

    return MoneroTransactionSetOutputAck(
        tx_out=tx_out_bin,
        vouti_hmac=hmac_vouti,
        rsig_data=_return_rsig_data(rsig),
        out_pk=out_pk_bin,
        ecdh_info=ecdh_info_bin,
    )


async def _validate(state: State, dst_entr, dst_entr_hmac):
    if state.current_input_index + 1 != state.input_count:
        raise ValueError("Invalid number of inputs")
    if dst_entr.amount <= 0:
        raise ValueError("Destination with wrong amount: %s" % dst_entr.amount)

    # HMAC check of the destination
    dst_entr_hmac_computed = await hmac_encryption_keys.gen_hmac_tsxdest(
        state.key_hmac, dst_entr, state.current_output_index
    )
    if not common.ct_equal(dst_entr_hmac, dst_entr_hmac_computed):
        raise ValueError("HMAC invalid")
    del (dst_entr_hmac, dst_entr_hmac_computed)
    state.mem_trace(3, True)


async def _set_out_tx_out(state: State, dst_entr, tx_out_key):
    """
    Manually serializes TxOut(0, TxoutToKey(key)) and calculates hmac.
    """
    tx_out_bin = bytearray(34)
    tx_out_bin[0] = 0  # amount varint
    tx_out_bin[1] = 2  # variant code TxoutToKey
    crypto.encodepoint_into(tx_out_bin, tx_out_key, 2)
    state.mem_trace(8)

    # Tx header prefix hashing
    state.tx_prefix_hasher.buffer(tx_out_bin)
    state.mem_trace(9, True)

    # Hmac dst_entr
    hmac_vouti = await hmac_encryption_keys.gen_hmac_vouti(
        state.key_hmac, dst_entr, tx_out_bin, state.current_output_index
    )
    state.mem_trace(10, True)
    return tx_out_bin, hmac_vouti


def _range_proof(state, amount, rsig_data):
    """
    Computes rangeproof
    In order to optimize incremental transaction build, the mask computation is changed compared
    to the official Monero code. In the official code, the input pedersen commitments are computed
    after range proof in such a way summed masks for commitments (alpha) and rangeproofs (ai) are equal.

    In order to save roundtrips we compute commitments randomly and then for the last rangeproof
    a[63] = (\\sum_{i=0}^{num_inp}alpha_i - \\sum_{i=0}^{num_outs-1} amasks_i) - \\sum_{i=0}^{62}a_i

    The range proof is incrementally hashed to the final_message.
    """
    from apps.monero.xmr import ring_ct

    mask = state.output_masks[state.current_output_index]
    provided_rsig = None
    if rsig_data and rsig_data.rsig and len(rsig_data.rsig) > 0:
        provided_rsig = rsig_data.rsig
    if not state.rsig_offload and provided_rsig:
        raise misc.TrezorError("Provided unexpected rsig")

    # Batching
    bidx = _get_rsig_batch(state, state.current_output_index)
    batch_size = state.rsig_grouping[bidx]
    last_in_batch = _is_last_in_batch(state, state.current_output_index, bidx)
    if state.rsig_offload and provided_rsig and not last_in_batch:
        raise misc.TrezorError("Provided rsig too early")
    if state.rsig_offload and last_in_batch and not provided_rsig:
        raise misc.TrezorError("Rsig expected, not provided")

    # Batch not finished, skip range sig generation now
    if not last_in_batch:
        return None, mask

    # Rangeproof
    # Pedersen commitment on the value, mask from the commitment, range signature.
    C, rsig = None, None

    state.mem_trace("pre-rproof" if __debug__ else None, collect=True)
    if not state.rsig_offload and state.use_bulletproof:
        """Bulletproof calculation in trezor"""
        rsig = ring_ct.prove_range_bp_batch(state.output_amounts, state.output_masks)
        state.mem_trace("post-bp" if __debug__ else None, collect=True)

        # Incremental BP hashing
        # BP is hashed with raw=False as hash does not contain L, R
        # array sizes compared to the serialized bulletproof format
        # thus direct serialization cannot be used.
        state.full_message_hasher.rsig_val(rsig, True, raw=False)
        state.mem_trace("post-bp-hash" if __debug__ else None, collect=True)

        rsig = misc.dump_rsig_bp(rsig)
        state.mem_trace(
            "post-bp-ser, size: %s" % len(rsig) if __debug__ else None, collect=True
        )

    elif not state.rsig_offload and not state.use_bulletproof:
        """Borromean calculation in trezor"""
        C, mask, rsig = ring_ct.prove_range_chunked(amount, mask)
        del (ring_ct)

        # Incremental hashing
        state.full_message_hasher.rsig_val(rsig, False, raw=True)
        _check_out_commitment(state, amount, mask, C)

    elif state.rsig_offload and state.use_bulletproof:
        """Bulletproof calculated on host, verify in trezor"""
        from apps.monero.xmr.serialize_messages.tx_rsig_bulletproof import Bulletproof

        # TODO this should be tested
        # last_in_batch = True (see above) so this is fine
        masks = state.output_masks[
            1 + state.current_output_index - batch_size : 1 + state.current_output_index
        ]
        bp_obj = misc.parse_msg(rsig_data.rsig, Bulletproof)
        rsig_data.rsig = None

        # BP is hashed with raw=False as hash does not contain L, R
        # array sizes compared to the serialized bulletproof format
        # thus direct serialization cannot be used.
        state.full_message_hasher.rsig_val(bp_obj, True, raw=False)
        res = ring_ct.verify_bp(bp_obj, state.output_amounts, masks)
        state.assrt(res, "BP verification fail")
        state.mem_trace("BP verified" if __debug__ else None, collect=True)
        del (bp_obj, ring_ct)

    elif state.rsig_offload and not state.use_bulletproof:
        """Borromean offloading not supported"""
        raise misc.TrezorError(
            "Unsupported rsig state (Borromean offloaded is not supported)"
        )

    else:
        raise misc.TrezorError("Unexpected rsig state")

    state.mem_trace("rproof" if __debug__ else None, collect=True)
    if state.current_output_index + 1 == state.output_count:
        # output masks and amounts are not needed anymore
        state.output_amounts = []
        state.output_masks = []
    return rsig, mask


def _return_rsig_data(rsig):
    if rsig is None:
        return None
    from trezor.messages.MoneroTransactionRsigData import MoneroTransactionRsigData

    if isinstance(rsig, list):
        return MoneroTransactionRsigData(rsig_parts=rsig)
    else:
        return MoneroTransactionRsigData(rsig=rsig)


def _get_ecdh_info_and_out_pk(state: State, tx_out_key, amount, mask, amount_key):
    """
    Calculates the Pedersen commitment C = aG + bH and returns it as CtKey.
    Also encodes the two items - `mask` and `amount` - into ecdh info,
    so the recipient is able to reconstruct the commitment.
    """
    from apps.monero.xmr.serialize_messages.ct_keys import CtKey

    out_pk = CtKey(
        dest=crypto.encodepoint(tx_out_key),
        mask=crypto.encodepoint(crypto.gen_commitment(mask, amount)),
    )
    state.sumout = crypto.sc_add(state.sumout, mask)
    state.output_sk_masks.append(mask)

    # masking of mask and amount
    ecdh_info = _ecdh_encode(mask, amount, crypto.encodeint(amount_key))

    # Manual ECDH info serialization
    ecdh_info_bin = bytearray(64)
    utils.memcpy(ecdh_info_bin, 0, ecdh_info.mask, 0, 32)
    utils.memcpy(ecdh_info_bin, 32, ecdh_info.amount, 0, 32)
    gc.collect()

    return out_pk, ecdh_info_bin


def _ecdh_encode(mask, amount, amount_key):
    """
    Output recipients need be able to reconstruct the amount commitments.
    This means the blinding factor `mask` and `amount` must be communicated
    to the receiver somehow.

    The mask and amount are stored as:
    - mask = mask + Hs(amount_key)
    - amount = amount + Hs(Hs(amount_key))
    Because the receiver can derive the `amount_key` they can
    easily derive both mask and amount as well.
    """
    from apps.monero.xmr.serialize_messages.tx_ecdh import EcdhTuple

    ecdh_info = EcdhTuple(mask=mask, amount=crypto.sc_init(amount))
    amount_key_hash_single = crypto.hash_to_scalar(amount_key)
    amount_key_hash_double = crypto.hash_to_scalar(
        crypto.encodeint(amount_key_hash_single)
    )

    ecdh_info.mask = crypto.sc_add(ecdh_info.mask, amount_key_hash_single)
    ecdh_info.amount = crypto.sc_add(ecdh_info.amount, amount_key_hash_double)
    return _recode_ecdh(ecdh_info)


def _recode_ecdh(ecdh_info):
    """
    In-place ecdh_info tuple recoding
    """
    ecdh_info.mask = crypto.encodeint(ecdh_info.mask)
    ecdh_info.amount = crypto.encodeint(ecdh_info.amount)
    return ecdh_info


def _set_out_additional_keys(state: State, dst_entr):
    """
    If needed (decided in step 1), additional tx keys are calculated
    for this particular output.
    """
    if not state.need_additional_txkeys:
        return None

    additional_txkey_priv = crypto.random_scalar()

    if dst_entr.is_subaddress:
        # R=r*D
        additional_txkey = crypto.scalarmult(
            crypto.decodepoint(dst_entr.addr.spend_public_key), additional_txkey_priv
        )
    else:
        # R=r*G
        additional_txkey = crypto.scalarmult_base(additional_txkey_priv)

    state.additional_tx_public_keys.append(crypto.encodepoint(additional_txkey))
    state.additional_tx_private_keys.append(additional_txkey_priv)
    return additional_txkey_priv


def _set_out_derivation(state: State, dst_entr, additional_txkey_priv):
    """
    Calculates derivation which is then used in the one-time address as
    `P = H(derivation)*G + B`.
    For change outputs the derivation equals a*R, because we know the
    private view key. For others it is either `r*A` for traditional
    addresses, or `s*C` for subaddresses. Both `r` and `s` are random
    scalars, `s` is used in the context of subaddresses, but it's
    basically the same thing.
    """
    from apps.monero.xmr.sub.addr import addr_eq

    change_addr = state.change_address()
    if change_addr and addr_eq(dst_entr.addr, change_addr):
        # sending change to yourself; derivation = a*R
        derivation = crypto.generate_key_derivation(
            state.tx_pub, state.creds.view_key_private
        )

    else:
        # sending to the recipient; derivation = r*A (or s*C in the subaddress scheme)
        if dst_entr.is_subaddress and state.need_additional_txkeys:
            deriv_priv = additional_txkey_priv
        else:
            deriv_priv = state.tx_priv
        derivation = crypto.generate_key_derivation(
            crypto.decodepoint(dst_entr.addr.view_public_key), deriv_priv
        )
    return derivation


def _check_out_commitment(state: State, amount, mask, C):
    state.assrt(
        crypto.point_eq(
            C,
            crypto.point_add(crypto.scalarmult_base(mask), crypto.scalarmult_h(amount)),
        ),
        "OutC fail",
    )


def _is_last_in_batch(state: State, idx, bidx):
    """
    Returns true if the current output is last in the rsig batch
    """
    batch_size = state.rsig_grouping[bidx]
    return (idx - sum(state.rsig_grouping[:bidx])) + 1 == batch_size


def _get_rsig_batch(state: State, idx):
    """
    Returns index of the current rsig batch
    """
    r = 0
    c = 0
    while c < idx + 1:
        c += state.rsig_grouping[r]
        r += 1
    return r - 1
