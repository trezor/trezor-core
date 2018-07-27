
from apps.monero.xmr.serialize.base_types import UInt8, UVarintType
from apps.monero.xmr.serialize.erefs import eref
from apps.monero.xmr.serialize.message_types import ContainerType, MessageType
from apps.monero.xmr.serialize_messages.base import ECKey
from apps.monero.xmr.serialize_messages.ct_keys import CtKey, CtkeyM, CtkeyV, KeyM, KeyV
from apps.monero.xmr.serialize_messages.tx_ecdh import EcdhInfo, EcdhTuple
from apps.monero.xmr.serialize_messages.tx_prefix import TransactionPrefix, TxinToKey
from apps.monero.xmr.serialize_messages.tx_rsig import RctType
from apps.monero.xmr.serialize_messages.tx_rsig_boro import RangeSig
from apps.monero.xmr.serialize_messages.tx_rsig_bulletproof import Bulletproof
from apps.monero.xmr.serialize_messages.tx_sig import (
    Signature,
    SignatureArray,
    get_signature_size,
)


class MgSig(MessageType):
    __slots__ = ("ss", "cc", "II")

    @classmethod
    def f_specs(cls):
        return (("ss", KeyM), ("cc", ECKey))


class RctSigBase(MessageType):
    __slots__ = (
        "type",
        "txnFee",
        "message",
        "mixRing",
        "pseudoOuts",
        "ecdhInfo",
        "outPk",
    )

    @classmethod
    def f_specs(cls):
        return (
            ("type", UInt8),
            ("txnFee", UVarintType),
            ("message", ECKey),
            ("mixRing", CtkeyM),
            ("pseudoOuts", KeyV),
            ("ecdhInfo", EcdhInfo),
            ("outPk", CtkeyV),
        )

    async def serialize_rctsig_base(self, ar, inputs, outputs):
        """
        Custom serialization
        :param ar:
        :type ar: x.Archive
        :return:
        """
        await self._msg_field(ar, idx=0)
        if self.type == RctType.Null:
            return
        if (
            self.type != RctType.Full
            and self.type != RctType.FullBulletproof
            and self.type != RctType.Simple
            and self.type != RctType.SimpleBulletproof
        ):
            raise ValueError("Unknown type")

        await self._msg_field(ar, idx=1)
        if self.type == RctType.Simple:
            await ar.prepare_container(inputs, eref(self, "pseudoOuts"), KeyV)
            if ar.writing and len(self.pseudoOuts) != inputs:
                raise ValueError("pseudoOuts size mismatch")

            for i in range(inputs):
                await ar.field(eref(self.pseudoOuts, i), KeyV.ELEM_TYPE)

        await ar.prepare_container(outputs, eref(self, "ecdhInfo"), EcdhTuple)
        if ar.writing and len(self.ecdhInfo) != outputs:
            raise ValueError("EcdhInfo size mismatch")

        for i in range(outputs):
            await ar.field(eref(self.ecdhInfo, i), EcdhInfo.ELEM_TYPE)

        await ar.prepare_container((outputs), eref(self, "outPk"), CtKey)
        if ar.writing and len(self.outPk) != outputs:
            raise ValueError("outPk size mismatch")

        for i in range(outputs):
            await ar.field(eref(self.outPk[i], "mask"), ECKey)


class RctSigPrunable(MessageType):
    __slots__ = ("rangeSigs", "bulletproofs", "MGs", "pseudoOuts")

    @classmethod
    def f_specs(cls):
        return (
            ("rangeSigs", ContainerType, RangeSig),
            ("bulletproofs", ContainerType, Bulletproof),
            ("MGs", ContainerType, MgSig),
            ("pseudoOuts", KeyV),
        )

    async def serialize_rctsig_prunable(self, ar, type, inputs, outputs, mixin):
        """
        Serialize rct sig
        :param ar:
        :type ar: x.Archive
        :param type:
        :param inputs:
        :param outputs:
        :param mixin:
        :return:
        """
        if type == RctType.Null:
            return True

        if (
            type != RctType.Full
            and type != RctType.FullBulletproof
            and type != RctType.Simple
            and type != RctType.SimpleBulletproof
        ):
            raise ValueError("Unknown type")

        if type == RctType.SimpleBulletproof or type == RctType.FullBulletproof:
            if len(self.bulletproofs) != outputs:
                raise ValueError("Bulletproofs size mismatch")

            await ar.prepare_container(
                outputs, eref(self, "bulletproofs"), elem_type=Bulletproof
            )
            for i in range(len(self.bulletproofs)):
                await ar.field(elem=eref(self.bulletproofs, i), elem_type=Bulletproof)

        else:
            await ar.prepare_container(
                outputs, eref(self, "rangeSigs"), elem_type=RangeSig
            )
            if len(self.rangeSigs) != outputs:
                raise ValueError("rangeSigs size mismatch")

            for i in range(len(self.rangeSigs)):
                await ar.field(elem=eref(self.rangeSigs, i), elem_type=RangeSig)

        # We keep a byte for size of MGs, because we don't know whether this is
        # a simple or full rct signature, and it's starting to annoy the hell out of me
        mg_elements = (
            inputs if type == RctType.Simple or type == RctType.SimpleBulletproof else 1
        )
        await ar.prepare_container(mg_elements, eref(self, "MGs"), elem_type=MgSig)
        if len(self.MGs) != mg_elements:
            raise ValueError("MGs size mismatch")

        for i in range(mg_elements):
            # We save the MGs contents directly, because we want it to save its
            # arrays and matrices without the size prefixes, and the load can't
            # know what size to expect if it's not in the data

            await ar.prepare_container(
                mixin + 1, eref(self.MGs[i], "ss"), elem_type=KeyM
            )
            if ar.writing and len(self.MGs[i].ss) != mixin + 1:
                raise ValueError("MGs size mismatch")

            for j in range(mixin + 1):
                mg_ss2_elements = 1 + (
                    1
                    if type == RctType.Simple or type == RctType.SimpleBulletproof
                    else inputs
                )
                await ar.prepare_container(
                    mg_ss2_elements, eref(self.MGs[i].ss, j), elem_type=KeyM.ELEM_TYPE
                )

                if ar.writing and len(self.MGs[i].ss[j]) != mg_ss2_elements:
                    raise ValueError("MGs size mismatch 2")

                for k in range(mg_ss2_elements):
                    await ar.field(eref(self.MGs[i].ss[j], k), elem_type=KeyV.ELEM_TYPE)

            await ar.field(eref(self.MGs[i], "cc"), elem_type=ECKey)

        if type == RctType.SimpleBulletproof:
            await ar.prepare_container(inputs, eref(self, "pseudoOuts"), elem_type=KeyV)
            if ar.writing and len(self.pseudoOuts) != inputs:
                raise ValueError("pseudoOuts size mismatch")

            for i in range(inputs):
                await ar.field(eref(self.pseudoOuts, i), elem_type=KeyV.ELEM_TYPE)


class RctSig(RctSigBase):
    @classmethod
    def f_specs(cls):
        return RctSigBase.f_specs() + (("p", RctSigPrunable),)


class Transaction(TransactionPrefix):
    @classmethod
    def f_specs(cls):
        return TransactionPrefix.f_specs() + (
            ("signatures", ContainerType, SignatureArray),
            ("rct_signatures", RctSig),
        )

    async def serialize_archive(self, ar):
        """
        Serialize the transaction
        :param ar:
        :type ar: x.Archive
        :return:
        """
        # Transaction prefix serialization first.
        await ar.message(self, TransactionPrefix)

        if self.version == 1:
            await ar.prepare_container(
                len(self.vin), eref(self, "signatures"), elem_type=SignatureArray
            )
            signatures_not_expected = len(self.signatures) == 0
            if not signatures_not_expected and len(self.vin) != len(self.signatures):
                raise ValueError("Signature size mismatch")

            for i in range(len(self.vin)):
                sig_size = get_signature_size(self.vin[i])
                if signatures_not_expected:
                    if 0 == sig_size:
                        continue
                    else:
                        raise ValueError("Unexpected sig")

                await ar.prepare_container(
                    sig_size, eref(self.signatures, i), elem_type=Signature
                )
                if sig_size != len(self.signatures[i]):
                    raise ValueError("Unexpected sig size")

                await ar.message(self.signatures[i], Signature)

        else:
            if len(self.vin) == 0:
                return

            await ar.prepare_message(eref(self, "rct_signatures"), RctSig)
            await self.rct_signatures.serialize_rctsig_base(
                ar, len(self.vin), len(self.vout)
            )

            if self.rct_signatures.type != RctType.Null:
                mixin_size = (
                    len(self.vin[0].key_offsets) - 1
                    if len(self.vin) > 0 and isinstance(self.vin[0], TxinToKey)
                    else 0
                )
                await ar.prepare_message(eref(self.rct_signatures, "p"), RctSigPrunable)
                await self.rct_signatures.p.serialize_rctsig_prunable(
                    ar,
                    self.rct_signatures.type,
                    len(self.vin),
                    len(self.vout),
                    mixin_size,
                )
        return self
