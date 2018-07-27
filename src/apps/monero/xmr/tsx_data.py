from apps.monero.xmr.serialize.base_types import BoolType, UVarintType
from apps.monero.xmr.serialize.message_types import BlobType, ContainerType, MessageType
from apps.monero.xmr.serialize_messages.base import SecretKey
from apps.monero.xmr.serialize_messages.tx_dest_entry import TxDestinationEntry


class TsxData(MessageType):
    """
    TsxData, initial input to the transaction processing.
    Serialization structure for easy hashing.
    """

    __slots__ = (
        "version",
        "payment_id",
        "unlock_time",
        "outputs",
        "change_dts",
        "num_inputs",
        "mixin",
        "fee",
        "account",
        "minor_indices",
        "is_multisig",
        "exp_tx_prefix_hash",
        "use_tx_keys",
        "is_bulletproof",
    )

    @classmethod
    def f_specs(cls):
        return (
            ("version", UVarintType),
            ("payment_id", BlobType),
            ("unlock_time", UVarintType),
            ("outputs", ContainerType, TxDestinationEntry),
            ("change_dts", TxDestinationEntry),
            ("num_inputs", UVarintType),
            ("mixin", UVarintType),
            ("fee", UVarintType),
            ("account", UVarintType),
            ("minor_indices", ContainerType, UVarintType),
            ("is_multisig", BoolType),
            ("exp_tx_prefix_hash", BlobType),  # expected prefix hash, bail on error
            ("use_tx_keys", ContainerType, SecretKey),  # use this secret key, multisig
            ("is_bulletproof", BoolType),
        )

    def __init__(self, payment_id=None, outputs=None, change_dts=None, **kwargs):
        super().__init__(**kwargs)

        self.payment_id = payment_id
        self.change_dts = change_dts
        self.fee = 0
        self.account = 0
        self.minor_indices = [0]
        self.outputs = outputs if outputs else []  # type: list[TxDestinationEntry]
        self.is_multisig = False
        self.is_bulletproof = False
        self.exp_tx_prefix_hash = b""
        self.use_tx_keys = []
