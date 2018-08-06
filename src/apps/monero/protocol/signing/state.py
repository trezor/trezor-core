import gc
from micropython import const

from trezor import log

from apps.monero.xmr import crypto


class TprefixStub:
    __slots__ = ("version", "unlock_time", "vin", "vout", "extra")

    def __init__(self, **kwargs):
        for kw in kwargs:
            setattr(self, kw, kwargs[kw])


class State:

    STEP_INP = const(100)
    STEP_PERM = const(200)
    STEP_VINI = const(300)
    STEP_ALL_IN = const(350)
    STEP_OUT = const(400)
    STEP_ALL_OUT = const(500)
    STEP_MLSAG = const(600)
    STEP_SIGN = const(700)

    def __init__(self, ctx):
        self.ctx = ctx

        """
        Account credentials
        type: AccountCreds
        - view private/public key
        - spend private/public key
        - and its corresponding address
        """
        self.creds = None

        """
        Encryption keys
        """
        self.key_hmac = None
        self.key_enc = None

        """
        Transaction keys
        - also denoted as r/R
        - tx_priv is a random number
        - tx_pub is equal to `r*G` or `r*D` for subaddresses
        - for subaddresses the `r` is commonly denoted as `s`, however it is still just a random number
        - the keys are used to derive the one time address and its keys (P = H(A*r)*G + B)
        """
        self.tx_priv = None
        self.tx_pub = None

        self.need_additional_txkeys = False
        self.use_bulletproof = False
        self.use_simple_rct = False
        self.input_count = 0
        self.output_count = 0
        self.output_change = None
        self.mixin = 0
        self.fee = 0
        self.account_idx = 0  # wallet sub-address major index

        self.additional_tx_private_keys = []
        self.additional_tx_public_keys = []
        self.current_input_index = -1
        self.current_output_index = -1
        self.summary_inputs_money = 0
        self.summary_outs_money = 0
        self.input_secrets = []
        self.output_sk_masks = []
        self.output_pk_masks = []  # commitments
        self.output_amounts = []
        self.output_masks = []

        self.rsig_grouping = []
        self.rsig_offload = 0
        self.sumout = crypto.sc_0()
        self.sumpouts_alphas = crypto.sc_0()
        self.subaddresses = {}
        self.tx = None
        self.source_permutation = []  # sorted by key images
        self.tx_prefix_hasher = None
        self.tx_prefix_hash = None
        self.full_message_hasher = None
        self.full_message = None  # pre-MLSAG hash
        self._init()

    def _init(self):
        from apps.monero.xmr.sub.keccak_hasher import KeccakXmrArchive
        from apps.monero.xmr.sub.mlsag_hasher import PreMlsagHasher

        self.tx = TprefixStub(vin=[], vout=[], extra=b"")
        self.tx_prefix_hasher = KeccakXmrArchive()
        self.full_message_hasher = PreMlsagHasher()

    def mem_trace(self, x=None, collect=False):
        if __debug__:
            log.debug(
                __name__,
                "Log trace: %s, ... F: %s A: %s",
                x,
                gc.mem_free(),
                gc.mem_alloc(),
            )
        if collect:
            gc.collect()

    def assrt(self, condition, msg=None):
        if condition:
            return
        raise ValueError("Assertion error%s" % (" : %s" % msg if msg else ""))

    def change_address(self):
        return self.output_change.addr if self.output_change else None

    def get_rct_type(self):
        """
        RCTsig type (simple/full x Borromean/Bulletproof)
        :return:
        """
        from apps.monero.xmr.serialize_messages.tx_rsig import RctType

        if self.use_simple_rct:
            return RctType.FullBulletproof if self.use_bulletproof else RctType.Simple
        else:
            return RctType.Full
