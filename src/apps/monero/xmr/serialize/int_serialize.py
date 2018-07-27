_UINT_BUFFER = bytearray(1)


async def load_uint(reader, width):
    """
    Constant-width integer serialization
    :param reader:
    :param width:
    :return:
    """
    buffer = _UINT_BUFFER
    result = 0
    shift = 0
    for _ in range(width):
        await reader.areadinto(buffer)
        result += buffer[0] << shift
        shift += 8
    return result


async def dump_uint(writer, n, width):
    """
    Constant-width integer serialization
    :param writer:
    :param n:
    :param width:
    :return:
    """
    buffer = _UINT_BUFFER
    for _ in range(width):
        buffer[0] = n & 0xff
        await writer.awrite(buffer)
        n >>= 8


def uvarint_size(n):
    """
    Returns size in bytes n would occupy serialized as varint
    :param n:
    :return:
    """
    bts = 0 if n != 0 else 1
    while n:
        n >>= 7
        bts += 1
    return bts


def load_uvarint_b(buffer):
    """
    Variable int deserialization, synchronous from buffer.
    :param buffer:
    :return:
    """
    result = 0
    idx = 0
    byte = 0x80
    while byte & 0x80:
        byte = buffer[idx]
        result += (byte & 0x7F) << (7 * idx)
        idx += 1
    return result


def dump_uvarint_b(n):
    """
    Serializes uvarint to the buffer
    :param n:
    :return:
    """
    buffer = bytearray(uvarint_size(n))
    return dump_uvarint_b_into(n, buffer, 0)


def dump_uvarint_b_into(n, buffer, offset=0):
    """
    Serializes n as variable size integer to the provided buffer.
    Buffer has to ha
    :param n:
    :param buffer:
    :param offset:
    :return:
    """
    shifted = True
    while shifted:
        shifted = n >> 7
        buffer[offset] = (n & 0x7F) | (0x80 if shifted else 0x00)
        offset += 1
        n = shifted
    return buffer


def load_uint_b(buffer, width):
    """
    Loads fixed size integer from the buffer
    :param buffer:
    :return:
    """
    result = 0
    for idx in range(width):
        result += buffer[idx] << (8 * idx)
    return result


def dump_uint_b(n, width):
    """
    Serializes fixed size integer to the buffer
    :param n:
    :param width:
    :return:
    """
    buffer = bytearray(width)
    return dump_uvarint_b_into(n, buffer, 0)


def dump_uint_b_into(n, width, buffer, offset=0):
    """
    Serializes fixed size integer to the buffer
    :param n:
    :param width:
    :return:
    """
    for idx in range(width):
        buffer[idx + offset] = n & 0xff
        n >>= 8
    return buffer
