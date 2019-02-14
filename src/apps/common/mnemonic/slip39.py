from trezor.crypto import slip39

from apps.common import mnemonic, storage


class Slip39Share:
    def __init__(self, index: int, threshold: int, id: bytes, share: bytes):
        self.index = index
        self.threshold = threshold
        self.id = id
        self.share = share

    def get_id(self) -> bytes:
        return self.id

    def get_threshold(self) -> int:
        return self.threshold

    def get_share(self) -> bytes:
        return self.share


def generate(strength: int, entropy: bytes, count: int = None, threshold: int = None):
    return slip39.generate(strength, entropy, count, threshold)


def get_type():
    return mnemonic.TYPE_SLIP39


def process_single(words: list) -> bytes:
    """
    Receives single mnemonic and processes it.
    Returns None if more shares are needed.
    """
    slip39share = _parse_share(words)
    if not storage.is_slip39_in_progress():
        _store_start(slip39share)
        if slip39share.get_threshold() != 1:
            return None
    else:
        remaining = _store_next(slip39share)
        if remaining != 0:
            return None

    # combine shares and returns
    print(storage.get_slip39_shares())
    return _combine(storage.get_slip39_shares())


def process_all(mnemonics: list):
    """
    Receives all mnemonics and processes
    it into pre-master secret which is usually then store in the storage.
    """
    shares = []
    for m in mnemonics:
        s = _parse_share(m)
        # TODO: check IDs, checksums etc.
        shares.append(s.get_share())

    return _combine(shares)


def store(secret: bytes, needs_backup: bool = False, no_backup: bool = False):
    storage.store_mnemonic(secret, mnemonic.TYPE_SLIP39, needs_backup, no_backup)
    storage.clear_slip39_data()


def restore() -> str:
    raise NotImplementedError()


def check():
    # TODO
    return True


def _combine(shares: list) -> bytes:
    # TODO
    return shares[0]


def _store_start(s: Slip39Share):
    storage.set_slip39_in_progress(True)
    print(s.get_id())
    storage.set_slip39_id(s.get_id())
    storage.set_slip39_shares(s.get_share(), s.get_threshold(), s.get_threshold())
    storage.set_slip39_remaining(s.get_threshold() - 1)
    storage.set_slip39_threshold(s.get_threshold())


def _store_next(s: Slip39Share):
    if s.get_id() != storage.get_slip39_id():
        raise ValueError(
            "Share identifiers do not match %s vs %s",
            s.get_id(),
            storage.get_slip39_id(),
        )
    remaining = storage.get_slip39_remaining()
    storage.set_slip39_shares(s.get_share(), s.get_threshold(), remaining)
    remaining -= 1
    storage.set_slip39_remaining(remaining)
    return remaining


def _parse_share(words: list):
    # TODO validate checksum (here? should do crypto)
    ind, t, id, s = slip39.parse(words)
    return Slip39Share(ind, t, id, s)
