from apps.monero.xmr.serialize.base_types import UInt32
from apps.monero.xmr.serialize.message_types import MessageType
from apps.monero.xmr.serialize_messages.base import ECPublicKey


class AccountPublicAddress(MessageType):
    __slots__ = ("m_spend_public_key", "m_view_public_key")

    @classmethod
    def f_specs(cls):
        return (("m_spend_public_key", ECPublicKey), ("m_view_public_key", ECPublicKey))


class SubaddressIndex(MessageType):
    __slots__ = ("major", "minor")

    @classmethod
    def f_specs(cls):
        return (("major", UInt32), ("minor", UInt32))
