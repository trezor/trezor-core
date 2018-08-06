from trezor.messages.MoneroGetWatchKey import MoneroGetWatchKey
from trezor.messages.MoneroWatchKey import MoneroWatchKey

from apps.monero.controller import misc
from apps.monero.layout import confirms
from apps.monero.xmr import crypto


async def get_watch_only(ctx, msg: MoneroGetWatchKey):
    address_n = msg.address_n or ()
    await confirms.require_confirm_watchkey(ctx)
    creds = await misc.monero_get_creds(ctx, address_n, msg.network_type)
    return MoneroWatchKey(
        watch_key=crypto.encodeint(creds.view_key_private), address=creds.address
    )
