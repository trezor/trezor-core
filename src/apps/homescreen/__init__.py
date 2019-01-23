from trezor import config, utils, wire
from trezor.messages import MessageType
from trezor.messages.Features import Features
from trezor.messages.Success import Success
from trezor.wire import protobuf_workflow, register

from apps.common import cache, storage

if False:
    from trezor.messages.Cancel import Cancel
    from trezor.messages.ClearSession import ClearSession
    from trezor.messages.GetFeatures import GetFeatures
    from trezor.messages.Initialize import Initialize
    from trezor.messages.Ping import Ping


def get_features() -> Features:
    f = Features()
    f.vendor = "trezor.io"
    f.language = "english"
    f.major_version = utils.VERSION_MAJOR
    f.minor_version = utils.VERSION_MINOR
    f.patch_version = utils.VERSION_PATCH
    f.revision = utils.GITREV
    f.model = utils.MODEL
    f.device_id = storage.get_device_id()
    f.label = storage.get_label()
    f.initialized = storage.is_initialized()
    f.pin_protection = config.has_pin()
    f.pin_cached = config.has_pin()
    f.passphrase_protection = storage.has_passphrase()
    f.passphrase_cached = cache.has_passphrase()
    f.needs_backup = storage.needs_backup()
    f.unfinished_backup = storage.unfinished_backup()
    f.no_backup = storage.no_backup()
    f.flags = storage.get_flags()
    return f


async def handle_Initialize(ctx: wire.Context, msg: Initialize) -> Features:
    if msg.state is None or msg.state != cache.get_state(prev_state=bytes(msg.state)):
        cache.clear(msg.skip_passphrase)
    return get_features()


async def handle_GetFeatures(ctx: wire.Context, msg: GetFeatures) -> Features:
    return get_features()


async def handle_ClearSession(ctx: wire.Context, msg: ClearSession) -> Success:
    cache.clear()
    return Success(message="Session cleared")


async def handle_Cancel(ctx: wire.Context, msg: Cancel) -> None:
    raise wire.ActionCancelled("Cancelled")


async def handle_Ping(ctx: wire.Context, msg: Ping) -> Success:
    if msg.button_protection:
        from apps.common.confirm import require_confirm
        from trezor.messages.ButtonRequestType import ProtectCall
        from trezor.ui.text import Text

        await require_confirm(ctx, Text("Confirm"), ProtectCall)
    if msg.passphrase_protection:
        from apps.common.request_passphrase import protect_by_passphrase

        await protect_by_passphrase(ctx)
    return Success(message=msg.message)


def boot() -> None:
    register(MessageType.Initialize, protobuf_workflow, handle_Initialize)
    register(MessageType.GetFeatures, protobuf_workflow, handle_GetFeatures)
    register(MessageType.ClearSession, protobuf_workflow, handle_ClearSession)
    register(MessageType.Cancel, protobuf_workflow, handle_Cancel)
    register(MessageType.Ping, protobuf_workflow, handle_Ping)
