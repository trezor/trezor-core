import gc

from trezor import log
from trezor.messages.MessageType import (
    DebugMoneroDiagRequest,
    MoneroGetAddress,
    MoneroGetWatchKey,
    MoneroKeyImageSyncRequest,
    MoneroTransactionSignRequest,
)
from trezor.wire import protobuf_workflow, register


# persistent state objects
class Holder(object):
    def __init__(self):
        self.ctx_sign = None
        self.ctx_ki = None


STATE = Holder()


def dispatch_MoneroGetAddress(*args, **kwargs):
    from apps.monero.get_address import layout_monero_get_address

    return layout_monero_get_address(*args, **kwargs)


def dispatch_MoneroGetWatchKey(*args, **kwargs):
    from apps.monero.get_watch_only import layout_monero_get_watch_only

    return layout_monero_get_watch_only(*args, **kwargs)


def dispatch_MoneroTsxSign(*args, **kwargs):
    from apps.monero.sign_tx import layout_sign_tx

    return layout_sign_tx(STATE, *args, **kwargs)


def dispatch_MoneroKeyImageSync(*args, **kwargs):
    from apps.monero.key_image_sync import layout_key_image_sync

    return layout_key_image_sync(STATE, *args, **kwargs)


def dispatch_MoneroDiag(*args, **kwargs):
    log.debug(__name__, "----diagnostics")
    gc.collect()
    from apps.monero.diag import dispatch_diag

    return dispatch_diag(*args, **kwargs)


def boot():
    register(MoneroGetAddress, protobuf_workflow, dispatch_MoneroGetAddress)
    register(MoneroGetWatchKey, protobuf_workflow, dispatch_MoneroGetWatchKey)
    register(MoneroTransactionSignRequest, protobuf_workflow, dispatch_MoneroTsxSign)
    register(MoneroKeyImageSyncRequest, protobuf_workflow, dispatch_MoneroKeyImageSync)
    register(DebugMoneroDiagRequest, protobuf_workflow, dispatch_MoneroDiag)
