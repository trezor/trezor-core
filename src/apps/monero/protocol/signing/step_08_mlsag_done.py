"""
After all outputs were processed we can finalize the full message
and return its hash.

The name of this step 'mlsag_done' is somewhat unfortunate and
will most likely be changed or merged to step 7.
"""

from .state import State

from apps.monero.layout import confirms


async def mlsag_done(state: State):
    from trezor.messages.MoneroTransactionMlsagDoneAck import (
        MoneroTransactionMlsagDoneAck,
    )

    await confirms.transaction_step(state.ctx, state.STEP_MLSAG)

    _out_pk(state)
    state.full_message_hasher.rctsig_base_done()
    state.current_output_index = -1
    state.current_input_index = -1

    state.full_message = state.full_message_hasher.get_digest()
    state.full_message_hasher = None

    return MoneroTransactionMlsagDoneAck(full_message_hash=state.full_message)


def _out_pk(state: State):
    """
    Hashes out_pk into the full message.
    """
    if state.output_count != len(state.output_pk_commitments):
        raise ValueError("Invalid number of ecdh")

    for out in state.output_pk_commitments:
        state.full_message_hasher.set_out_pk_commitment(out)
