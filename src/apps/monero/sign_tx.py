#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import gc
import micropython

from trezor import log


async def layout_sign_tx(state, ctx, msg):
    gc.threshold(gc.mem_free() // 4 + gc.mem_alloc())
    log.debug(
        __name__,
        "############################ TSX. Free: {} Allocated: {} thr: {}".format(
            gc.mem_free(), gc.mem_alloc(), gc.mem_free() // 4 + gc.mem_alloc()
        ),
    )
    gc.collect()
    micropython.mem_info()

    from apps.monero.protocol.tsx_sign import TsxSigner

    log.debug(
        __name__,
        "TsxSigner. Free: {} Allocated: {}".format(gc.mem_free(), gc.mem_alloc()),
    )
    log.debug(__name__, "TsxState: %s", state.ctx_sign)
    gc.collect()

    try:
        signer = TsxSigner()
        res = await signer.sign(ctx, state.ctx_sign, msg)
        if await signer.should_purge():
            state.ctx_sign = None
        else:
            state.ctx_sign = await signer.state_save()

        return res

    except Exception as e:
        state.ctx_sign = None
        log.error(__name__, "Tsx exception: %s %s", type(e), e)
        raise
