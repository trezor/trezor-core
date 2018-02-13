from trezor import res, ui, wire


async def request_passphrase_on_display(ctx):
    from trezor.ui.passphrase import PassphraseKeyboard, CANCELLED

    ui.display.clear()
    passphrase = await PassphraseKeyboard('Enter passphrase')
    if passphrase == CANCELLED:
        return False
    return passphrase


async def request_passphrase_on_host(ctx):
    from trezor.messages.FailureType import ActionCancelled
    from trezor.messages.PassphraseRequest import PassphraseRequest
    from trezor.messages.wire_types import PassphraseAck, Cancel
    from trezor.ui.text import Text

    text = Text(
        'Passphrase entry', ui.ICON_RESET,
        'Please, type passphrase', 'on connected host.')
    ui.display.clear()
    text.render()
    ack = await ctx.call(PassphraseRequest(), PassphraseAck, Cancel)
    if ack.MESSAGE_WIRE_TYPE == Cancel:
        raise wire.FailureError(ActionCancelled, 'Passphrase cancelled')
    return ack.passphrase


async def request_passphrase(ctx):
    from trezor.ui.text import Text
    from trezor.ui.entry_select import EntrySelector

    res = False
    text = Text(
        'Enter passphrase', ui.ICON_RESET,
        'Where to enter your', 'passphrase?')

    while not res:
        ui.display.clear()
        entry = EntrySelector(text)
        entry_type = await entry

        if entry_type == 1:
            res = await request_passphrase_on_host(ctx)
        else:
            res = await request_passphrase_on_display(ctx)

    return res


async def protect_by_passphrase(ctx):
    from apps.common import storage

    if storage.has_passphrase():
        return await request_passphrase(ctx)
    else:
        return ''
