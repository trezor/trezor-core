from apps.common.confirm import require_confirm
from apps.common.signverify import split_message
from trezor.messages.StellarVerifyMessage import StellarVerifyMessage
from trezor.messages.Success import Success
from trezor import ui
from trezor import wire
from trezor.crypto.curve import ed25519
from trezor.ui.text import Text

STELLAR_CURVE = 'ed25519'


async def verify_message(ctx, msg: StellarVerifyMessage):
    try:
        res = ed25519.verify(msg.public_key, msg.signature, msg.message)
    except ValueError:
        raise wire.DataError('Invalid signature')  # todo better?

    if not res:
        raise wire.DataError('Invalid signature')

    await require_confirm_verify_message(ctx, msg.message)

    return Success(message='Message verified')


async def require_confirm_verify_message(ctx, message):
    message = split_message(message)
    content = Text('Verify message', ui.ICON_DEFAULT, max_lines=5, *message)
    await require_confirm(ctx, content)
