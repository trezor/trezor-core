from trezor import wire
from trezor.messages.Success import Success

from apps.common import storage

if False:
    from trezor.messages.ApplyFlags import ApplyFlags


async def apply_flags(ctx: wire.Context, msg: ApplyFlags) -> Success:
    if msg.flags is not None:
        storage.set_flags(msg.flags)
    return Success(message="Flags applied")
