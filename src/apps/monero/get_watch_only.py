from trezor.messages.MoneroGetWatchKey import MoneroGetWatchKey
from trezor.messages.MoneroWatchKey import MoneroWatchKey

from apps.monero import layout
from apps.monero.controller import wrapper
from apps.monero.xmr import crypto


async def layout_monero_get_watch_only(ctx, msg: MoneroGetWatchKey):
    address_n = msg.address_n or ()
    await layout.require_confirm_watchkey(ctx)
    creds = await wrapper.monero_get_creds(ctx, address_n, msg.network_type)
    return MoneroWatchKey(
        watch_key=crypto.encodeint(creds.view_key_private), address=creds.address
    )
