import gc

from trezor import log
from trezor.messages import MessageType


async def key_image_sync(ctx, msg):
    state = None

    while True:
        res, state, accept_msgs = await key_image_sync_step(ctx, msg, state)
        if accept_msgs is None:
            break
        msg = await ctx.call(res, *accept_msgs)

    return res


async def key_image_sync_step(ctx, msg, state):
    if __debug__:
        log.debug(__name__, "f: %s a: %s", gc.mem_free(), gc.mem_alloc())
        log.debug(__name__, "s: %s", state)

    from apps.monero.protocol import key_image_sync

    gc.collect()

    if msg.MESSAGE_WIRE_TYPE == MessageType.MoneroKeyImageExportInitRequest:
        state = key_image_sync.KeyImageSync(ctx=ctx)
        return (
            await state.init(ctx, msg),
            state,
            (MessageType.MoneroKeyImageSyncStepRequest,),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroKeyImageSyncStepRequest:
        return (
            await state.sync(ctx, msg),
            state,
            (
                MessageType.MoneroKeyImageSyncStepRequest,
                MessageType.MoneroKeyImageSyncFinalRequest,
            ),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroKeyImageSyncFinalRequest:
        return await state.final(ctx, msg), None, None

    else:
        raise ValueError("Unknown error")
