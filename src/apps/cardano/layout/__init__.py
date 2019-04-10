from micropython import const

from trezor import ui
from trezor.messages import ButtonRequestType, MessageType
from trezor.messages.ButtonRequest import ButtonRequest
from trezor.ui.confirm import CONFIRMED, Confirm, HoldToConfirm
from trezor.ui.scroll import Paginated
from trezor.ui.text import Text
from trezor.utils import chunks, format_amount

if __debug__:
    from apps.debug import confirm_signal


def format_coin_amount(amount):
    return "%s %s" % (format_amount(amount, 6), "ADA")


async def confirm_sending(ctx, amount, to):
    to_lines = list(chunks(to, 17))

    t1 = Text("Confirm transaction", ui.ICON_SEND, ui.GREEN)
    t1.normal("Confirm sending:")
    t1.bold(format_coin_amount(amount))
    t1.normal("to:")
    t1.bold(to_lines[0])

    PER_PAGE = const(4)
    pages = [t1]
    if len(to_lines) > 1:
        to_pages = list(chunks(to_lines[1:], PER_PAGE))
        for page in to_pages:
            t = Text("Confirm transaction", ui.ICON_SEND, ui.GREEN)
            for line in page:
                t.bold(line)
            pages.append(t)

    pages[-1] = Confirm(pages[-1])
    paginated = Paginated(pages)

    await ctx.call(ButtonRequest(code=ButtonRequestType.Other), MessageType.ButtonAck)

    if __debug__:
        return await ctx.wait(paginated, confirm_signal) is CONFIRMED
    else:
        return await ctx.wait(paginated) is CONFIRMED


async def confirm_transaction(ctx, amount, fee, network_name):
    t1 = Text("Confirm transaction", ui.ICON_SEND, ui.GREEN)
    t1.normal("Total amount:")
    t1.bold(format_coin_amount(amount))
    t1.normal("including fee:")
    t1.bold(format_coin_amount(fee))

    t2 = Text("Confirm transaction", ui.ICON_SEND, ui.GREEN)
    t2.normal("Network:")
    t2.bold(network_name)

    paginated = Paginated([t1, HoldToConfirm(t2)])

    await ctx.call(ButtonRequest(code=ButtonRequestType.Other), MessageType.ButtonAck)

    if __debug__:
        return await ctx.wait(paginated, confirm_signal) is CONFIRMED
    else:
        return await ctx.wait(paginated) is CONFIRMED
