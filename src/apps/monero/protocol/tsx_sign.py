#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018
import gc

from trezor import log

from apps.monero.controller import misc


class TsxSigner(object):
    """
    Monero Transaction signer.
    Provides interface to the host, packages messages.
    """

    def __init__(self):
        from apps.monero.controller import iface

        self.ctx = None
        self.tsx_ctr = 0
        self.err_ctr = 0
        self.tsx_obj = None  # type: TTransactionBuilder
        self.creds = None  # type: apps.monero.xmr.sub.creds.AccountCreds
        self.iface = iface.get_iface()
        self.debug = True
        self.purge = False

    async def tsx_exc_handler(self, e):
        """
        Handles the exception thrown in the Trezor processing. Clears transaction state.
        We could use decorator/wrapper for message calls but not sure how uPython handles them
        so now are entry points wrapped in try-catch.

        :param e:
        :return:
        """
        if self.debug:
            log.warning(__name__, "Transaction exception: %s: %s", type(e), e)

        self.err_ctr += 1
        self.purge = True
        self.tsx_obj = None  # clear transaction object
        await self.iface.transaction_error(e)

    async def should_purge(self):
        """
        Delete global state?
        :return:
        """
        return self.purge or (self.tsx_obj and self.tsx_obj.is_terminal())

    async def setup(self, msg):
        from apps.monero.controller import wrapper

        self.creds = await wrapper.monero_get_creds(
            self.ctx, msg.address_n or (), msg.network_type
        )

    async def restore(self, state):
        from apps.monero.protocol.tsx_sign_builder import TTransactionBuilder

        self.tsx_obj = TTransactionBuilder(self, creds=self.creds, state=state)

    async def state_save(self):
        try:
            s = self.tsx_obj.state_save()
            self.tsx_obj = None
        finally:
            gc.collect()
        return s

    async def sign(self, ctx, state, msg):
        """
        Main multiplex point
        :param ctx:
        :param state:
        :param msg:
        :return:
        """
        from apps.monero.controller import iface

        self.ctx = ctx
        self.iface = iface.get_iface(ctx)
        gc.collect()

        log.debug(__name__, "sign()")
        log.debug(
            __name__, "Mem Free: {} Allocated: {}".format(gc.mem_free(), gc.mem_alloc())
        )

        if msg.init:
            log.debug(__name__, "setup")
            await self.setup(msg.init)
        await self.restore(state if not msg.init else None)

        if msg.init:
            log.debug(__name__, "sign_init")
            return await self.tsx_init(msg.init.tsx_data)
        elif msg.set_input:
            log.debug(__name__, "sign_inp")
            return await self.tsx_set_input(msg.set_input)
        elif msg.input_permutation:
            log.debug(__name__, "sign_perm")
            return await self.tsx_inputs_permutation(msg.input_permutation)
        elif msg.input_vini:
            log.debug(__name__, "sign_vin")
            return await self.tsx_input_vini(msg.input_vini)
        elif msg.set_output:
            log.debug(__name__, "sign_out")
            return await self.tsx_set_output1(msg.set_output)
        elif msg.all_out_set:
            log.debug(__name__, "sign_out_set")
            return await self.tsx_all_out1_set(msg.all_out_set)
        elif msg.mlsag_done:
            log.debug(__name__, "sign_done")
            return await self.tsx_mlsag_done()
        elif msg.sign_input:
            log.debug(__name__, "sign_sinp")
            return await self.tsx_sign_input(msg.sign_input)
        elif msg.final_msg:
            log.debug(__name__, "sign_final")
            return await self.tsx_sign_final(msg.final_msg)
        else:
            raise ValueError("Unknown message")

    async def tsx_init(self, tsx_data):
        """
        Initialize transaction state.
        :param tsx_data:
        :return:
        """
        self.tsx_ctr += 1
        try:
            tsxd = await misc.translate_tsx_data(tsx_data)
            del tsx_data

            return await self.tsx_obj.init_transaction(tsxd, self.tsx_ctr)
        except Exception as e:
            await self.tsx_exc_handler(e)
            raise

    async def tsx_set_input(self, msg):
        """
        Sets UTXO one by one.
        Computes spending secret key, key image. tx.vin[i] + HMAC, Pedersen commitment on amount.

        If number of inputs is small, in-memory mode is used = alpha, pseudo_outs are kept in the Trezor.
        Otherwise pseudo_outs are offloaded with HMAC, alpha is offloaded encrypted under AES-GCM() with
        key derived for exactly this purpose.

        :param msg
        :return:
        """
        try:
            src_entr = await misc.parse_src_entry(msg.src_entr)
            del msg.src_entr

            return await self.tsx_obj.set_input(src_entr)
        except Exception as e:
            await self.tsx_exc_handler(e)
            raise

    async def tsx_inputs_permutation(self, msg):
        """
        Set permutation on the inputs - sorted by key image on host.

        :return:
        """
        try:
            return await self.tsx_obj.tsx_inputs_permutation(msg.perm)
        except Exception as e:
            await self.tsx_exc_handler(e)
            raise

    async def tsx_input_vini(self, msg):
        """
        Set tx.vin[i] for incremental tx prefix hash computation.
        After sorting by key images on host.

        :return:
        """
        try:
            src_entr = await misc.parse_src_entry(msg.src_entr)
            vini = await misc.parse_vini(msg.vini)
            del msg.src_entr
            del msg.vini

            return await self.tsx_obj.input_vini(
                src_entr, vini, msg.vini_hmac, msg.pseudo_out, msg.pseudo_out_hmac
            )
        except Exception as e:
            await self.tsx_exc_handler(e)
            raise

    async def tsx_set_output1(self, msg):
        """
        Set destination entry one by one.
        Computes destination stealth address, amount key, range proof + HMAC, out_pk, ecdh_info.

        :param msg
        :return:
        """
        try:
            dst_entr = await misc.parse_dst_entry(msg.dst_entr)
            del msg.dst_entr

            return await self.tsx_obj.set_out1(dst_entr, msg.dst_entr_hmac)
        except Exception as e:
            await self.tsx_exc_handler(e)
            raise

    async def tsx_all_out1_set(self, msg=None):
        """
        All outputs were set in this phase. Computes additional public keys (if needed), tx.extra and
        transaction prefix hash.
        Adds additional public keys to the tx.extra

        :return: tx.extra, tx_prefix_hash
        """
        try:
            return await self.tsx_obj.all_out1_set()

        except misc.TrezorTxPrefixHashNotMatchingError as e:
            await self.tsx_exc_handler(e)

            from trezor.messages.Failure import Failure
            from apps.monero.controller.wrapper import exc2str

            return Failure(code=10, message=exc2str(e))

        except Exception as e:
            await self.tsx_exc_handler(e)
            raise

    async def tsx_mlsag_done(self, msg=None):
        """
        MLSAG message computed.

        :return:
        """
        try:
            return await self.tsx_obj.mlsag_done()
        except Exception as e:
            await self.tsx_exc_handler(e)
            raise

    async def tsx_sign_input(self, msg):
        """
        Generates a signature for one input.

        :return:
        """
        try:
            src_entr = await misc.parse_src_entry(msg.src_entr)
            vini = await misc.parse_vini(msg.vini)
            del msg.src_entr
            del msg.vini

            return await self.tsx_obj.sign_input(
                src_entr,
                vini,
                msg.vini_hmac,
                msg.pseudo_out,
                msg.pseudo_out_hmac,
                msg.alpha_enc,
                msg.spend_enc,
            )
        except Exception as e:
            await self.tsx_exc_handler(e)
            raise

    async def tsx_sign_final(self, msg=None):
        """
        Final message.
        Offloading tx related data, encrypted.

        :return:
        """
        try:
            return await self.tsx_obj.final_msg()
        except Exception as e:
            await self.tsx_exc_handler(e)
            raise
