from ubinascii import hexlify

from trezor import config, ui, wire, workflow
from trezor.crypto import hashlib, random
from trezor.messages import ButtonRequestType, MessageType
from trezor.messages.EntropyRequest import EntropyRequest
from trezor.messages.Success import Success
from trezor.pin import pin_to_int
from trezor.ui.num_pad import NumPad
from trezor.ui.text import Text
from trezor.utils import chunks

from apps.common import mnemonic, storage
from apps.common.confirm import require_confirm
from apps.management.change_pin import request_pin_confirm
from apps.management.common import layout

if __debug__:
    from apps import debug


async def reset_device(ctx, msg):
    _validate(msg, msg.slip39)

    await _show_intro(ctx, msg.slip39)

    # request new PIN
    if msg.pin_protection:
        newpin = await request_pin_confirm(ctx)
    else:
        newpin = ""

    if msg.slip39:
        module = mnemonic.slip39
        shares_count, threshold = await _ask_counts(ctx)

    else:
        module = mnemonic.bip39
        shares_count, threshold = None, None

    # generate and display internal entropy
    int_entropy = random.bytes(32)
    if __debug__:
        debug.reset_internal_entropy = int_entropy
    if msg.display_random:
        await _show_entropy(ctx, int_entropy)

    # request external entropy and compute mnemonic
    ent_ack = await ctx.call(EntropyRequest(), MessageType.EntropyAck)
    entropy = _mix_entropy(int_entropy, ent_ack.entropy)
    mnemonics = module.generate(msg.strength, entropy, shares_count, threshold)
    print("generated mnemonics:")
    print(mnemonics)

    if not msg.skip_backup and not msg.no_backup:
        await layout.show_mnemonics(ctx, mnemonics)

    # write PIN into storage
    if not config.change_pin(pin_to_int(""), pin_to_int(newpin)):
        raise wire.ProcessError("Could not change PIN")

    # write settings and mnemonic into storage
    storage.load_settings(label=msg.label, use_passphrase=msg.passphrase_protection)
    secret = module.process_all(mnemonics)
    module.store(secret=secret, needs_backup=msg.skip_backup, no_backup=msg.no_backup)

    # show success message.  if we skipped backup, it's possible that homescreen
    # is still running, uninterrupted.  restart it to pick up new label.
    if not msg.skip_backup and not msg.no_backup:
        await _show_success(ctx)
    else:
        workflow.restartdefault()

    return Success(message="Initialized")


def _validate(msg, is_slip39):
    # validate parameters and device state
    if msg.strength not in (128, 256):
        if is_slip39:
            raise wire.ProcessError("Invalid strength (has to be 128 or 256 bits)")
        elif msg.strength != 192:
            raise wire.ProcessError("Invalid strength (has to be 128, 192 or 256 bits)")

    if msg.display_random and (msg.skip_backup or msg.no_backup):
        raise wire.ProcessError("Can't show internal entropy when backup is skipped")
    if storage.is_initialized():
        raise wire.UnexpectedMessage("Already initialized")
    if (msg.skip_backup or msg.no_backup) and is_slip39:
        raise wire.ProcessError("Both no/skip backup flag and Shamir SLIP-39 required.")


def _mix_entropy(int_entropy: bytes, ext_entropy: bytes) -> bytes:
    ehash = hashlib.sha256()
    ehash.update(int_entropy)
    ehash.update(ext_entropy)
    return ehash.digest()


async def _show_intro(ctx, slip39=False):
    text = Text("Create a new wallet", ui.ICON_RESET, new_lines=False)
    text.normal("Do you want to create")
    text.br()
    if slip39:
        text.normal("a new SLIP-39 wallet?")
    else:
        text.normal("a new wallet?")
    text.br()
    text.br_half()
    text.normal("By continuing you agree")
    text.br()
    text.normal("to")
    text.bold("https://trezor.io/tos")

    await require_confirm(ctx, text, code=ButtonRequestType.ResetDevice)


async def _ask_counts(ctx):
    shares = await NumPad("Set number of shares", 1, 32)
    threshold = await NumPad("Set threshold", 1, shares + 1)

    return shares, threshold


async def _show_entropy(ctx, entropy: bytes):
    entropy_str = hexlify(entropy).decode()
    lines = chunks(entropy_str, 16)
    text = Text("Internal entropy", ui.ICON_RESET)
    text.mono(*lines)
    await require_confirm(ctx, text, ButtonRequestType.ResetDevice)


async def _show_success(ctx):
    text = Text("Backup is done!", ui.ICON_CONFIRM, icon_color=ui.GREEN)
    text.normal(
        "Never make a digital",
        "copy of your recovery",
        "seed and never upload",
        "it online!",
    )
    await require_confirm(
        ctx, text, ButtonRequestType.ResetDevice, confirm="Finish setup", cancel=None
    )
