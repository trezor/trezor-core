from trezorcrypto import random

from .slip39_wordlist import wordlist

# TODO
MNEMONIC_KEYS = ("ab", "cd", "ef", "ghij", "klm", "nopq", "rs", "tuv", "wxyz")
MNEMONIC_KEYS_LETTERS = dict()

if not MNEMONIC_KEYS_LETTERS:
    for k, v in enumerate(MNEMONIC_KEYS, 1):
        for s in v:
            MNEMONIC_KEYS_LETTERS[s] = str(k)


def find_word(prefix: str, t9=False):
    """
    Return the first word from the wordlist starting with prefix.
    """
    return find_words(prefix, t9, single=True)


def find_words(prefix: str, t9=False, single=False) -> list:
    words = []
    if not t9:
        for _, word in wordlist:
            if word.startswith(prefix):
                if single:
                    return word
                else:
                    words.append(word)
    else:
        button = _prefix_to_pressed_buttons(prefix[:4])
        for key, word in wordlist:
            if key.startswith(button):
                if single:
                    return word
                else:
                    words.append(word)
    return words


def _prefix_to_pressed_buttons(prefix: str):
    x = ""
    for p in prefix:
        x += MNEMONIC_KEYS_LETTERS[p]
    return x


def complete_word(prefix: str, t9=False) -> int:
    """
    Return possible 1-letter suffixes for given word prefix.
    Result is a bitmask, with 'a' on the lowest bit, 'b' on the second lowest, etc.
    """
    if not len(prefix):
        return 0xFFFFFFFF  # all letters

    mask = 0
    words = find_words(prefix, t9)
    for word in words:
        if len(word) == len(prefix):  # TODO!
            continue
        mask |= 1 << (ord(word[len(prefix)]) - 97)  # ord('a') == 97
    return mask


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
