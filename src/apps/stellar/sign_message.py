from apps.common.confirm import require_confirm
from apps.common.signverify import split_message
from trezor.crypto.curve import ed25519
from trezor.messages.StellarMessageSignature import StellarMessageSignature
from trezor.messages.StellarSignMessage import StellarSignMessage
from trezor.ui.text import Text
from trezor import ui
from ..common import seed

STELLAR_CURVE = 'ed25519'


async def sign_message(ctx, msg: StellarSignMessage):
    await require_confirm_sign_message(ctx, msg.message)

    node = await seed.derive_node(ctx, msg.address_n, STELLAR_CURVE)
    pubkey = seed.remove_ed25519_public_key_prefix(node.public_key())

    signature = ed25519.sign(node.private_key(), msg.message)

    sig = StellarMessageSignature()
    sig.public_key = pubkey
    sig.signature = signature
    return sig


async def require_confirm_sign_message(ctx, message: str):
    message = split_message(message)
    content = Text('Sign Stellar message', ui.ICON_DEFAULT, max_lines=5, *message)
    await require_confirm(ctx, content)
