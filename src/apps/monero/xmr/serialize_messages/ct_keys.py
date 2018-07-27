from micropython import const

from apps.monero.xmr.serialize.message_types import ContainerType, MessageType
from apps.monero.xmr.serialize_messages.base import ECKey

_c0 = const(0)
_c1 = const(1)
_c32 = const(32)
_c64 = const(64)


class Key64(ContainerType):
    FIX_SIZE = _c1
    SIZE = _c64
    ELEM_TYPE = ECKey


class KeyV(ContainerType):
    FIX_SIZE = _c0
    ELEM_TYPE = ECKey


class KeyM(ContainerType):
    FIX_SIZE = _c0
    ELEM_TYPE = KeyV


class KeyVFix(ContainerType):
    FIX_SIZE = _c1
    ELEM_TYPE = ECKey


class KeyMFix(ContainerType):
    FIX_SIZE = _c1
    ELEM_TYPE = KeyVFix


class CtKey(MessageType):
    __slots__ = ("dest", "mask")

    @classmethod
    def f_specs(cls):
        return (("dest", ECKey), ("mask", ECKey))


class CtkeyV(ContainerType):
    FIX_SIZE = 0
    ELEM_TYPE = CtKey


class CtkeyM(ContainerType):
    FIX_SIZE = 0
    ELEM_TYPE = CtkeyV
