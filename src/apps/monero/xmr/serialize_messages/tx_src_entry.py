from apps.monero.xmr.serialize.base_types import BoolType, SizeT, UInt64, UVarintType
from apps.monero.xmr.serialize.message_types import (
    ContainerType,
    MessageType,
    TupleType,
)
from apps.monero.xmr.serialize_messages.base import ECKey, ECPublicKey
from apps.monero.xmr.serialize_messages.ct_keys import CtKey


class MultisigKLRki(MessageType):
    @classmethod
    def f_specs(cls):
        return (("K", ECKey), ("L", ECKey), ("R", ECKey), ("ki", ECKey))


class OutputEntry(TupleType):
    @classmethod
    def f_specs(cls):
        return (UVarintType, CtKey)  # original: x.UInt64


class TxSourceEntry(MessageType):
    @classmethod
    def f_specs(cls):
        return (
            ("outputs", ContainerType, OutputEntry),
            ("real_output", SizeT),
            ("real_out_tx_key", ECPublicKey),
            ("real_out_additional_tx_keys", ContainerType, ECPublicKey),
            ("real_output_in_tx_index", UInt64),
            ("amount", UInt64),
            ("rct", BoolType),
            ("mask", ECKey),
            ("multisig_kLRki", MultisigKLRki),
        )
