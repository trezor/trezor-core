from apps.monero.xmr.serialize.message_types import ContainerType, MessageType
from apps.monero.xmr.serialize_messages.base import ECKey


class EcdhTuple(MessageType):
    __slots__ = ("mask", "amount")

    @classmethod
    def f_specs(cls):
        return (("mask", ECKey), ("amount", ECKey))


class EcdhInfo(ContainerType):
    ELEM_TYPE = EcdhTuple
