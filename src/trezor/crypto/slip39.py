from trezorcrypto import random

from .slip39_wordlist import wordlist


def find_word(prefix: str):
    """
    Return the first word from the wordlist starting with prefix.
    """
    raise NotImplementedError()


def complete_word(prefix: str) -> int:
    """
    Return possible 1-letter suffixes for given word prefix.
    Result is a bitmask, with 'a' on the lowest bit, 'b' on the second lowest, etc.
    """
    raise NotImplementedError()


def generate(strength: int, entropy: bytes, count: int, threshold: int) -> list:
    """
    Generate a mnemonic of given strength (128 or 256 bits).
    ! TODO mocked
    """
    if strength not in (128, 256):
        raise ValueError("Invalid strength for SLIP-39")

    mnemonics = list()
    id = [wordlist[random.uniform(1024)] for _ in range(3)]  # TODO: use random.sample

    for index in range(count):
        t_i = wordlist[threshold << 5 | index]
        share = [wordlist[random.uniform(1024)] for _ in range(strength // 10 + 1)]
        checksum = [wordlist[random.uniform(1024)] for _ in range(3)]
        mnemonic = id + [t_i] + share + checksum
        mnemonics.append(mnemonic)

    return mnemonics


def parse(words: list) -> (int, int, bytes, bytes):
    # TODO validate checksum
    t_i = wordlist.index(words[3])
    threshold = t_i >> 5
    index = t_i & 0x1F
    id = mnemonic_to_bytes(words[:3])
    share = mnemonic_to_bytes(words[4:-3])
    return index, threshold, id, share


def mnemonic_to_bytes(words: list) -> bytes:
    # TODO! THIS IS MOCK
    i = 0
    for m in words:
        i <<= 10
        i |= wordlist.index(m)
    return i.to_bytes(len(words) * 10 // 8, "big")


def from_data(data: bytes, count: int, threshold: int) -> str:
    """
    Generate a mnemonic from given data.
    """
    raise NotImplementedError()


def check(mnemonic: str) -> bool:
    """
    Check whether given mnemonic is valid.
    """
    print("WARNING: SLIP39 check not implemented")


def seed(secret: bytes, passphrase: str) -> bytes:
    """
    Generate seed from mnemonic and passphrase.
    """
    # TODO
    return secret
