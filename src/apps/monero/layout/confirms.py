from trezor import ui
from trezor.messages import ButtonRequestType
from trezor.ui.text import Text
from trezor.utils import chunks

from . import common

from apps.common.confirm import require_confirm, require_hold_to_confirm


async def confirm_out(ctx, dst, is_change=False, creds=None, int_payment=None):
    """
    Single transaction destination confirmation
    """
    from apps.monero.xmr.sub.addr import encode_addr
    from apps.monero.xmr.sub.xmr_net import net_version

    ver = net_version(creds.network_type, dst.is_subaddress, int_payment is not None)
    addr = encode_addr(
        ver, dst.addr.spend_public_key, dst.addr.view_public_key, int_payment
    )

    await require_confirm_tx(ctx, addr.decode("ascii"), dst.amount, is_change)


async def confirm_payment_id(ctx, payment_id):
    """
    Confirm payment ID
    """
    if payment_id is None:
        return

    await require_confirm_payment_id(ctx, payment_id)


async def confirm_transaction(ctx, tsx_data, creds=None):
    """
    Ask for confirmation from user
    """
    from apps.monero.xmr.sub.addr import get_change_addr_idx

    outs = tsx_data.outputs
    change_idx = get_change_addr_idx(outs, tsx_data.change_dts)

    has_integrated = (
        tsx_data.integrated_indices is not None and len(tsx_data.integrated_indices) > 0
    )
    has_payment = tsx_data.payment_id is not None and len(tsx_data.payment_id) > 0

    for idx, dst in enumerate(outs):
        is_change = change_idx is not None and idx == change_idx
        if is_change:
            continue
        if change_idx is None and dst.amount == 0 and len(outs) == 2:
            continue  # sweep, dummy tsx

        cur_payment = (
            tsx_data.payment_id
            if has_integrated and idx in tsx_data.integrated_indices
            else None
        )
        await confirm_out(ctx, dst, is_change, creds, cur_payment)

    if has_payment and not has_integrated:
        await confirm_payment_id(ctx, tsx_data.payment_id)

    await require_confirm_fee(ctx, tsx_data.fee)

    from trezor.ui.text import Text
    from trezor import ui
    from trezor import loop
    from trezor.ui import BACKLIGHT_DIM, BACKLIGHT_NORMAL

    await ui.backlight_slide(BACKLIGHT_DIM)
    slide = ui.backlight_slide(BACKLIGHT_NORMAL)

    text = Text("Signing transaction", ui.ICON_SEND, icon_color=ui.BLUE)
    text.normal("Signing...")

    await common.simple_text(text, tm=500)
    loop.schedule(slide)

    await loop.sleep(200 * 1000)


async def require_confirm_watchkey(ctx):
    content = Text("Confirm export", ui.ICON_SEND, icon_color=ui.GREEN)
    content.normal(*["Do you really want to", "export watch-only", "credentials?"])
    return await require_confirm(ctx, content, ButtonRequestType.SignTx)


async def require_confirm_keyimage_sync(ctx):
    content = Text("Confirm ki sync", ui.ICON_SEND, icon_color=ui.GREEN)
    content.normal(*["Do you really want to", "sync key images?"])
    return await require_confirm(ctx, content, ButtonRequestType.SignTx)


async def require_confirm_payment_id(ctx, payment_id):
    from ubinascii import hexlify
    from trezor import wire

    if not await common.naive_pagination(
        ctx,
        [ui.MONO] + list(chunks(hexlify((payment_id)), 16)),
        "Payment ID",
        ui.ICON_SEND,
        ui.GREEN,
    ):
        raise wire.ActionCancelled("Cancelled")


async def require_confirm_tx(ctx, to, value, is_change=False):
    from trezor import wire

    to_chunks = list(common.split_address(to))
    text = [ui.BOLD, common.format_amount(value), ui.MONO] + to_chunks
    conf_text = "Confirm send" if not is_change else "Con. change"
    if not await common.naive_pagination(
        ctx, text, conf_text, ui.ICON_SEND, ui.GREEN, 4
    ):
        raise wire.ActionCancelled("Cancelled")


async def require_confirm_fee(ctx, fee):
    content = Text("Confirm fee", ui.ICON_SEND, icon_color=ui.GREEN)
    content.bold(common.format_amount(fee))
    await require_hold_to_confirm(ctx, content, ButtonRequestType.ConfirmOutput)


async def transaction_error(ctx):
    from trezor import ui
    from trezor.ui.text import Text

    text = Text("Error", ui.ICON_SEND, icon_color=ui.RED)
    text.normal("Transaction failed")

    await common.ui_text(text, tm=500 * 1000)


async def transaction_finished(ctx):
    """
    Notifies the transaction has been completed (all data were sent)
    """
    from trezor import ui
    from trezor.ui.text import Text

    text = Text("Success", ui.ICON_SEND, icon_color=ui.GREEN)
    text.normal("Transaction signed")

    await common.ui_text(text, tm=500 * 1000)


async def transaction_step(ctx, step, sub_step=None, sub_step_total=None):
    from trezor import ui
    from trezor.ui.text import Text

    info = []
    if step == 100:
        info = ["Processing inputs", "%d/%d" % (sub_step + 1, sub_step_total)]
    elif step == 200:
        info = ["Sorting"]
    elif step == 300:
        info = [
            "Processing inputs",
            "phase 2",
            "%d/%d" % (sub_step + 1, sub_step_total),
        ]
    elif step == 400:
        info = ["Processing outputs", "%d/%d" % (sub_step + 1, sub_step_total)]
    elif step == 500:
        info = ["Postprocessing..."]
    elif step == 600:
        info = ["Postprocessing..."]
    elif step == 700:
        info = ["Signing inputs", "%d/%d" % (sub_step + 1, sub_step_total)]
    else:
        info = ["Processing..."]

    text = Text("Signing transaction", ui.ICON_SEND, icon_color=ui.BLUE)
    text.normal(*info)

    await common.simple_text(text, tm=10 * 1000)


async def confirm_ki_sync(ctx, init_msg):
    await require_confirm_keyimage_sync(ctx)
    return True


async def ki_error(ctx, e):
    # todo
    pass


async def ki_step(ctx, i):
    # todo
    pass


async def ki_finished(ctx):
    # todo
    pass
