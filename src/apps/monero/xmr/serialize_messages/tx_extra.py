
from apps.monero.xmr.serialize.base_types import SizeT, UInt8, UVarintType
from apps.monero.xmr.serialize.message_types import (
    BlobType,
    ContainerType,
    MessageType,
    VariantType,
)
from apps.monero.xmr.serialize_messages.base import ECPublicKey, Hash


class TxExtraPadding(MessageType):
    __slots__ = ("size",)
    TX_EXTRA_PADDING_MAX_COUNT = 255

    VARIANT_CODE = 0x0

    @classmethod
    def f_specs(cls):
        return (("size", SizeT),)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.size = 0

    async def serialize_archive(self, ar):
        if ar.writing:
            if self.size > self.TX_EXTRA_PADDING_MAX_COUNT:
                raise ValueError("Padding too big")
            for i in range(self.size):
                ar.uint(0, UInt8)

        else:
            self.size = 0
            buffer = bytearray(1)
            for i in range(self.TX_EXTRA_PADDING_MAX_COUNT + 1):
                self.size += 1
                try:
                    nread = await ar.iobj.areadinto(buffer)
                    if nread == 0:
                        break
                except EOFError:
                    break

                if buffer[0] != 0:
                    raise ValueError("Padding error")
        return self


class TxExtraPubKey(MessageType):
    __slots__ = ("pub_key",)
    VARIANT_CODE = 0x1

    @classmethod
    def f_specs(cls):
        return (("pub_key", ECPublicKey),)


class TxExtraNonce(MessageType):
    __slots__ = ("nonce",)
    VARIANT_CODE = 0x2

    @classmethod
    def f_specs(cls):
        return (("nonce", BlobType),)


class TxExtraMergeMiningTag(MessageType):
    VARIANT_CODE = 0x3

    @classmethod
    def f_specs(cls):
        return (
            ("field_len", UVarintType),
            ("depth", UVarintType),
            ("merkle_root", Hash),
        )


class TxExtraAdditionalPubKeys(MessageType):
    __slots__ = ("data",)
    VARIANT_CODE = 0x4

    @classmethod
    def f_specs(cls):
        return (("data", ContainerType, ECPublicKey),)


class TxExtraMysteriousMinergate(MessageType):
    __slots__ = ("data",)
    VARIANT_CODE = 0xde

    @classmethod
    def f_specs(cls):
        return (("data", BlobType),)


class TxExtraField(VariantType):
    @classmethod
    def f_specs(cls):
        return (
            ("tx_extra_padding", TxExtraPadding),
            ("tx_extra_pub_key", TxExtraPubKey),
            ("tx_extra_nonce", TxExtraNonce),
            ("tx_extra_merge_mining_tag", TxExtraMergeMiningTag),
            ("tx_extra_additional_pub_keys", TxExtraAdditionalPubKeys),
            ("tx_extra_mysterious_minergate", TxExtraMysteriousMinergate),
        )


class TxExtraFields(ContainerType):
    ELEM_TYPE = TxExtraField
