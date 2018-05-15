from trezor.wire import register, protobuf_workflow
from trezor.messages.wire_types import StellarGetPublicKey
from trezor.messages.wire_types import StellarSignMessage
from trezor.messages.wire_types import StellarVerifyMessage


def dispatch_StellarGetPublicKey(*args, **kwargs):
    from .get_public_key import get_public_key
    return get_public_key(*args, **kwargs)


def dispatch_StellarSignMessage(*args, **kwargs):
    from .sign_message import sign_message
    return sign_message(*args, **kwargs)


def dispatch_StellarVerifyMessage(*args, **kwargs):
    from .verify_message import verify_message
    return verify_message(*args, **kwargs)


def boot():
    register(StellarGetPublicKey, protobuf_workflow, dispatch_StellarGetPublicKey)
    register(StellarSignMessage, protobuf_workflow, dispatch_StellarSignMessage)
    register(StellarVerifyMessage, protobuf_workflow, dispatch_StellarVerifyMessage)
