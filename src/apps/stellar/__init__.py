from trezor.wire import register, protobuf_workflow
from trezor.messages.wire_types import StellarGetPublicKey
from trezor.messages.wire_types import StellarSignMessage


def dispatch_StellarGetPublicKey(*args, **kwargs):
    from .get_public_key import get_public_key
    return get_public_key(*args, **kwargs)


def dispatch_StellarSignMessage(*args, **kwargs):
    from .sign_message import sign_message
    return sign_message(*args, **kwargs)


def boot():
    register(StellarGetPublicKey, protobuf_workflow, dispatch_StellarGetPublicKey)
    register(StellarSignMessage, protobuf_workflow, dispatch_StellarSignMessage)
