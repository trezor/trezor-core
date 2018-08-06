from apps.monero.xmr import crypto
from apps.monero.xmr.serialize import int_serialize


class KeccakXmrArchive:
    def __init__(self, ctx=None):
        self.kwriter = get_keccak_writer(ctx=ctx)

    def ctx(self):
        return self.kwriter.ctx()

    def get_digest(self):
        return self.kwriter.get_digest()

    def buffer(self, buf):
        return self.kwriter.write(buf)

    def uvarint(self, i):
        int_serialize.dump_uvarint(self.kwriter, i)

    def uint(self, i, width):
        int_serialize.dump_uint(self.kwriter, i, width)


class AHashWriter:
    def __init__(self, hasher):
        self.hasher = hasher

    def write(self, buf):
        self.hasher.update(buf)
        return len(buf)

    async def awrite(self, buf):
        return self.write(buf)

    def get_digest(self, *args) -> bytes:
        return self.hasher.digest(*args)

    def ctx(self):
        return self.hasher


def get_keccak_writer(ctx=None):
    return AHashWriter(crypto.get_keccak() if ctx is None else ctx)
