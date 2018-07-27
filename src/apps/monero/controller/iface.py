#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


class TrezorInterface(object):
    def __init__(self, ctx=None):
        self.ctx = ctx

    def gctx(self, ctx):
        return ctx if ctx is not None else self.ctx

    async def restore_default(self):
        from trezor import workflow

        workflow.restartdefault()

    async def confirm_transaction(self, tsx_data, creds=None, ctx=None):
        """
        Ask for confirmation from user
        :param tsx_data:
        :param creds:
        :param ctx:
        :return:
        """
        from apps.monero.xmr.sub.addr import encode_addr, get_change_addr_idx
        from apps.monero.xmr.sub.xmr_net import net_version

        outs = tsx_data.outputs
        change_idx = get_change_addr_idx(outs, tsx_data.change_dts)

        if change_idx is not None:
            outs = [x for i, x in enumerate(outs) if i != change_idx] + [
                outs[change_idx]
            ]
            change_idx = len(outs) - 1

        from apps.monero import layout

        for idx, dst in enumerate(outs):
            addr = encode_addr(
                net_version(creds.network_type),
                dst.addr.m_spend_public_key,
                dst.addr.m_view_public_key,
            )
            is_change = change_idx and idx == change_idx
            await layout.require_confirm_tx(
                self.gctx(ctx), addr.decode("ascii"), dst.amount, is_change
            )

        await layout.require_confirm_fee(self.gctx(ctx), tsx_data.fee)

        from trezor.ui.text import Text
        from trezor import ui
        from trezor import loop
        from trezor import log
        from trezor import workflow
        from trezor.ui import BACKLIGHT_DIM, BACKLIGHT_NORMAL

        await ui.backlight_slide(BACKLIGHT_DIM)
        slide = ui.backlight_slide(BACKLIGHT_NORMAL)
        # await ui.backlight_slide(BACKLIGHT_NORMAL)

        text = Text("Signing transaction", ui.ICON_SEND, icon_color=ui.BLUE)
        text.normal("Signing...")

        try:
            layout = await layout.simple_text(text, tm=1000)
            log.debug(__name__, "layout: %s", layout)
            workflow.closedefault()
            workflow.onlayoutstart(layout)
            loop.schedule(slide)
            # display.clear()

        finally:
            pass
            # loop.close(slide)
            # workflow.onlayoutclose(layout)

        await loop.sleep(500 * 1000)
        return True

    async def transaction_error(self, *args, **kwargs):
        """
        Transaction error
        :return:
        """
        from trezor import ui
        from trezor.ui.text import Text
        from apps.monero import layout

        text = Text("Error", ui.ICON_SEND, icon_color=ui.RED)
        text.normal("Transaction failed")

        await layout.ui_text(text, tm=3 * 1000 * 1000)
        await self.restore_default()

    async def transaction_signed(self, ctx=None):
        """
        Notifies the transaction was completely signed
        :return:
        """

    async def transaction_finished(self, ctx=None):
        """
        Notifies the transaction has been completed (all data were sent)
        :return:
        """
        from trezor import ui
        from trezor.ui.text import Text
        from apps.monero import layout

        text = Text("Success", ui.ICON_SEND, icon_color=ui.GREEN)
        text.normal("Transaction signed")

        await layout.ui_text(text, tm=3 * 1000 * 1000)
        await self.restore_default()

    async def transaction_step(self, step, sub_step=None, sub_step_total=None):
        """
        Transaction progress
        :param step:
        :param sub_step:
        :param sub_step_total:
        :return:
        """
        from trezor import ui
        from trezor.ui.text import Text
        from apps.monero import layout

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

        await layout.simple_text(text, tm=10 * 1000)

    async def confirm_ki_sync(self, init_msg, ctx=None):
        """
        Ask confirmation on key image sync
        :param init_msg:
        :return:
        """
        from apps.monero import layout

        await layout.require_confirm_keyimage_sync(self.gctx(ctx))
        return True

    async def ki_error(self, e, ctx=None):
        """
        Key image sync error
        :param e:
        :return:
        """

    async def ki_step(self, i, ctx=None):
        """
        Key image sync step
        :param i:
        :return:
        """

    async def ki_finished(self, ctx=None):
        """
        Ki sync finished
        :return:
        """


def get_iface(ctx=None):
    return TrezorInterface(ctx)
