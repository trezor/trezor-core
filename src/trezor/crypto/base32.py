# Base32 implementation taken from the micropython-lib's base64 module
# https://github.com/micropython/micropython-lib/blob/master/base64/base64.py
#

import ubinascii
import ustruct

bytes_types = (bytes, bytearray)  # Types acceptable as binary data

_b32alphabet = {
    0: b'A',  9: b'J', 18: b'S', 27: b'3',
    1: b'B', 10: b'K', 19: b'T', 28: b'4',
    2: b'C', 11: b'L', 20: b'U', 29: b'5',
    3: b'D', 12: b'M', 21: b'V', 30: b'6',
    4: b'E', 13: b'N', 22: b'W', 31: b'7',
    5: b'F', 14: b'O', 23: b'X',
    6: b'G', 15: b'P', 24: b'Y',
    7: b'H', 16: b'Q', 25: b'Z',
    8: b'I', 17: b'R', 26: b'2',
    }

_b32tab = [v[0] for k, v in sorted(_b32alphabet.items())]
_b32rev = dict([(v[0], k) for k, v in _b32alphabet.items()])


def encode(s: bytes) -> str:
    """Encode a byte string using Base32.
    s is the byte string to encode.  The encoded byte string is returned.
    """
    if not isinstance(s, bytes_types):
        raise TypeError("expected bytes, not %s" % s.__class__.__name__)
    quanta, leftover = divmod(len(s), 5)
    # Pad the last quantum with zero bits if necessary
    if leftover:
        s = s + bytes(5 - leftover)  # Don't use += !
        quanta += 1
    encoded = bytearray()
    for i in range(quanta):
        # c1 and c2 are 16 bits wide, c3 is 8 bits wide.  The intent of this
        # code is to process the 40 bits in units of 5 bits.  So we take the 1
        # leftover bit of c1 and tack it onto c2.  Then we take the 2 leftover
        # bits of c2 and tack them onto c3.  The shifts and masks are intended
        # to give us values of exactly 5 bits in width.
        c1, c2, c3 = ustruct.unpack('!HHB', s[i*5:(i+1)*5])
        c2 += (c1 & 1) << 16 # 17 bits wide
        c3 += (c2 & 3) << 8  # 10 bits wide
        encoded += bytes([_b32tab[c1 >> 11],         # bits 1 - 5
                          _b32tab[(c1 >> 6) & 0x1f], # bits 6 - 10
                          _b32tab[(c1 >> 1) & 0x1f], # bits 11 - 15
                          _b32tab[c2 >> 12],         # bits 16 - 20 (1 - 5)
                          _b32tab[(c2 >> 7) & 0x1f], # bits 21 - 25 (6 - 10)
                          _b32tab[(c2 >> 2) & 0x1f], # bits 26 - 30 (11 - 15)
                          _b32tab[c3 >> 5],          # bits 31 - 35 (1 - 5)
                          _b32tab[c3 & 0x1f],        # bits 36 - 40 (1 - 5)
                          ])
    # Adjust for any leftover partial quanta
    if leftover == 1:
        encoded = encoded[:-6] + b'======'
    elif leftover == 2:
        encoded = encoded[:-4] + b'===='
    elif leftover == 3:
        encoded = encoded[:-3] + b'==='
    elif leftover == 4:
        encoded = encoded[:-1] + b'='

    return bytes(encoded).decode('utf-8')  # todo ok?


def decode(s: str, casefold=False, map01=None) -> bytes:
    """Decode a Base32 encoded byte string.
    s is the byte string to decode.  Optional casefold is a flag
    specifying whether a lowercase alphabet is acceptable as input.
    For security purposes, the default is False.
    RFC 3548 allows for optional mapping of the digit 0 (zero) to the
    letter O (oh), and for optional mapping of the digit 1 (one) to
    either the letter I (eye) or letter L (el).  The optional argument
    map01 when not None, specifies which letter the digit 1 should be
    mapped to (when map01 is not None, the digit 0 is always mapped to
    the letter O).  For security purposes the default is None, so that
    0 and 1 are not allowed in the input.
    The decoded byte string is returned.  binascii.Error is raised if
    the input is incorrectly padded or if there are non-alphabet
    characters present in the input.
    """
    s = _bytes_from_decode_data(s)
    quanta, leftover = divmod(len(s), 8)
    if leftover:
        raise ubinascii.Error('Incorrect padding')
    # Handle section 2.4 zero and one mapping.  The flag map01 will be either
    # False, or the character to map the digit 1 (one) to.  It should be
    # either L (el) or I (eye).
    if map01 is not None:
        map01 = _bytes_from_decode_data(map01)
        assert len(map01) == 1, repr(map01)
        s = s.translate(bytes.maketrans(b'01', b'O' + map01))
    if casefold:
        s = s.upper()
    # Strip off pad characters from the right.  We need to count the pad
    # characters because this will tell us how many null bytes to remove from
    # the end of the decoded string.
    padchars = s.find(b'=')
    if padchars > 0:
        padchars = len(s) - padchars
        s = s[:-padchars]
    else:
        padchars = 0

    # Now decode the full quanta
    parts = []
    acc = 0
    shift = 35
    for c in s:
        val = _b32rev.get(c)
        if val is None:
            raise ubinascii.Error('Non-base32 digit found')
        acc += _b32rev[c] << shift
        shift -= 5
        if shift < 0:
            parts.append(ubinascii.unhexlify(bytes('%010x' % acc, "ascii")))
            acc = 0
            shift = 35
    # Process the last, partial quanta
    last = ubinascii.unhexlify(bytes('%010x' % acc, "ascii"))
    if padchars == 0:
        last = b''                      # No characters
    elif padchars == 1:
        last = last[:-1]
    elif padchars == 3:
        last = last[:-2]
    elif padchars == 4:
        last = last[:-3]
    elif padchars == 6:
        last = last[:-4]
    else:
        raise ubinascii.Error('Incorrect padding')
    parts.append(last)
    return b''.join(parts)


def _bytes_from_decode_data(s):
    if isinstance(s, str):
        try:
            return s.encode('ascii')
#        except UnicodeEncodeError:
        except:
            raise ValueError('string argument should contain only ASCII characters')
    elif isinstance(s, bytes_types):
        return s
    else:
        raise TypeError("argument should be bytes or ASCII string, not %s" % s.__class__.__name__)
