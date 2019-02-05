from trezor import ui, wire
from trezor.messages import ButtonRequestType, MessageType
from trezor.messages.ButtonRequest import ButtonRequest
from trezor.ui.confirm import CONFIRMED, ConfirmDialog, HoldToConfirmDialog

if False:
    from typing import Any


@ui.layout
async def confirm(
    ctx: wire.Context, content: ui.Widget, code: int = None, *args: Any, **kwargs: Any
) -> bool:
    if code is None:
        code = ButtonRequestType.Other
    await ctx.call(ButtonRequest(code=code), MessageType.ButtonAck)

    dialog = ConfirmDialog(content, *args, **kwargs)

    return await ctx.wait(dialog) is CONFIRMED


@ui.layout
async def hold_to_confirm(
    ctx: wire.Context, content: ui.Widget, code: int = None, *args: Any, **kwargs: Any
) -> bool:
    if code is None:
        code = ButtonRequestType.Other
    await ctx.call(ButtonRequest(code=code), MessageType.ButtonAck)

    dialog = HoldToConfirmDialog(content, "Hold to confirm", *args, **kwargs)

    return await ctx.wait(dialog) is CONFIRMED


async def require_confirm(*args: Any, **kwargs: Any) -> None:
    confirmed = await confirm(*args, **kwargs)
    if not confirmed:
        raise wire.ActionCancelled("Cancelled")


async def require_hold_to_confirm(*args: Any, **kwargs: Any) -> None:
    confirmed = await hold_to_confirm(*args, **kwargs)
    if not confirmed:
        raise wire.ActionCancelled("Cancelled")
