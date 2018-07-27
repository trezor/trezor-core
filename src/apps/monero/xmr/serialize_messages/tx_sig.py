from apps.monero.xmr.serialize.erefs import eref
from apps.monero.xmr.serialize.message_types import ContainerType, MessageType
from apps.monero.xmr.serialize_messages.base import ECKey
from apps.monero.xmr.serialize_messages.tx_prefix import (
    TxinGen,
    TxinToKey,
    TxinToScript,
    TxinToScriptHash,
)


class Signature(MessageType):
    __slots__ = ("c", "r")

    @classmethod
    def f_specs(cls):
        return (("c", ECKey), ("r", ECKey))

    async def serialize_archive(self, ar):
        ar.field(eref(self, "c"), ECKey)
        ar.field(eref(self, "r"), ECKey)
        return self


class SignatureArray(ContainerType):
    FIX_SIZE = 0
    ELEM_TYPE = Signature


def get_signature_size(msg):
    """
    Returns a signature size for the input
    :param msg:
    :return:
    """
    if isinstance(msg, (TxinGen, TxinToScript, TxinToScriptHash)):
        return 0
    elif isinstance(msg, TxinToKey):
        return len(msg.key_offsets)
    else:
        raise ValueError("Unknown tx in")
