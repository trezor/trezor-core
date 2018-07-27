from trezor import ui
from trezor.messages import ButtonRequestType
from trezor.ui.text import Text
from trezor.utils import chunks

from apps.common.confirm import require_confirm, require_hold_to_confirm


async def require_confirm_watchkey(ctx):
    content = Text("Confirm export", ui.ICON_SEND, icon_color=ui.GREEN)
    content.normal(*["Do you really want to", "export watch-only", "credentials?"])
    return await require_confirm(ctx, content, ButtonRequestType.SignTx)


async def require_confirm_keyimage_sync(ctx):
    content = Text("Confirm ki sync", ui.ICON_SEND, icon_color=ui.GREEN)
    content.normal(*["Do you really want to", "sync key images?"])
    return await require_confirm(ctx, content, ButtonRequestType.SignTx)


async def require_confirm_tx_plain(ctx, to, value, is_change=False):
    content = Text(
        "Confirm " + ("sending" if not is_change else "change"),
        ui.ICON_SEND,
        icon_color=ui.GREEN,
    )
    content.bold(format_amount(value))
    content.normal("to")
    content.mono(*split_address(to))
    return await require_confirm(ctx, content, code=ButtonRequestType.SignTx)


@ui.layout
async def tx_dialog(
    ctx, code, content, cancel_btn, confirm_btn, cancel_style, confirm_style
):
    from trezor.messages import MessageType
    from trezor.messages.ButtonRequest import ButtonRequest
    from trezor.ui.confirm import ConfirmDialog

    await ctx.call(ButtonRequest(code=code), MessageType.ButtonAck)
    dialog = ConfirmDialog(
        content,
        cancel=cancel_btn,
        confirm=confirm_btn,
        cancel_style=cancel_style,
        confirm_style=confirm_style,
    )
    return await ctx.wait(dialog)


async def require_confirm_tx(ctx, to, value, is_change=False):
    from trezor import loop

    len_addr = (len(to) + 15) // 16
    if len_addr <= 2:
        return await require_confirm_tx_plain(ctx, to, value, is_change)

    else:
        to_chunks = list(split_address(to))
        from trezor import res, wire
        from trezor.ui.confirm import (
            CONFIRMED,
            CANCELLED,
            DEFAULT_CANCEL,
            DEFAULT_CONFIRM,
        )

        npages = 1 + ((len_addr - 2) + 3) // 4
        cur_step = 0
        code = ButtonRequestType.SignTx
        iback = res.load(ui.ICON_BACK)
        inext = res.load(ui.ICON_CLICK)

        while cur_step <= npages:
            text = []
            if cur_step == 0:
                text = [
                    ui.BOLD,
                    format_amount(value),
                    ui.NORMAL,
                    "to",
                    ui.MONO,
                ] + to_chunks[:2]
            else:
                off = 4 * (cur_step - 1)
                cur_chunks = to_chunks[2 + off : 2 + off + 4]
                ctext = [list(x) for x in zip([ui.MONO] * len(cur_chunks), cur_chunks)]
                for x in ctext:
                    text += x

            if cur_step == 0:
                cancel_btn = DEFAULT_CANCEL
                cancel_style = ui.BTN_CANCEL
                confirm_btn = inext
                confirm_style = ui.BTN_DEFAULT
            elif cur_step + 1 < npages:
                cancel_btn = iback
                cancel_style = ui.BTN_DEFAULT
                confirm_btn = inext
                confirm_style = ui.BTN_DEFAULT
            else:
                cancel_btn = iback
                cancel_style = ui.BTN_DEFAULT
                confirm_btn = DEFAULT_CONFIRM
                confirm_style = ui.BTN_CONFIRM

            conf_text = "Confirm send" if not is_change else "Con. change"
            content = Text(
                "%s %d/%d" % (conf_text, cur_step + 1, npages),
                ui.ICON_SEND,
                icon_color=ui.GREEN,
            )
            content.normal(*text)

            reaction = await tx_dialog(
                ctx, code, content, cancel_btn, confirm_btn, cancel_style, confirm_style
            )

            if cur_step == 0 and reaction == CANCELLED:
                raise wire.ActionCancelled("Cancelled")
            elif cur_step + 1 < npages and reaction == CONFIRMED:
                cur_step += 1
            elif cur_step + 1 >= npages and reaction == CONFIRMED:
                await loop.sleep(1000 * 1000)
                return
            elif reaction == CANCELLED:
                cur_step -= 1
            elif reaction == CONFIRMED:
                cur_step += 1


async def require_confirm_fee(ctx, fee):
    content = Text("Confirm fee", ui.ICON_SEND, icon_color=ui.GREEN)
    content.normal("Fee: ")
    content.bold(format_amount(fee))
    await require_hold_to_confirm(ctx, content, ButtonRequestType.ConfirmOutput)


@ui.layout
async def simple_wait(tm):
    from trezor import loop

    await loop.sleep(tm)


async def light_on():
    from trezor import loop

    slide = await ui.backlight_slide(ui.BACKLIGHT_NORMAL, delay=0)
    loop.schedule(slide)


@ui.layout
async def ui_text(text, tm=None) -> None:
    from trezor import loop

    text.render()

    if tm is not None:
        await loop.sleep(tm)


async def simple_text(text, tm=None) -> None:
    from trezor import loop
    from trezor.ui import display

    display.clear()
    text.render()

    if tm is not None:
        await loop.sleep(tm)


def format_amount(value):
    return "%f XMR" % (value / 1000000000000)


def split_address(address):
    return chunks(address, 16)
