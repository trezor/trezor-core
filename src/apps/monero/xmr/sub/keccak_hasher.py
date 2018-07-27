from apps.monero.xmr import crypto
from apps.monero.xmr.serialize import xmrserialize


class KeccakArchive(object):
    def __init__(self, ctx=None):
        self.kwriter = get_keccak_writer(ctx=ctx)
        self.ar = xmrserialize.Archive(self.kwriter, True)

    def ctx(self):
        return self.kwriter.ctx()

    def refresh(self, ctx=None, xser=None):
        if ctx is None:
            ctx = self.kwriter.ctx()
        if xser is None:
            xser = xmrserialize

        self.kwriter = get_keccak_writer(ctx=ctx)
        self.ar = xser.Archive(self.kwriter, True)
        return self.ar


class HashWrapper(object):
    def __init__(self, ctx):
        self.ctx = ctx

    def update(self, buf):
        if len(buf) == 0:
            return
        self.ctx.update(buf)

    def digest(self):
        return self.ctx.digest()

    def hexdigest(self):
        return self.ctx.hexdigest()


class AHashWriter:
    def __init__(self, hasher, sub_writer=None):
        self.hasher = hasher
        self.sub_writer = sub_writer

    async def awrite(self, buf):
        self.hasher.update(buf)
        if self.sub_writer:
            await self.sub_writer.awrite(buf)
        return len(buf)

    def get_digest(self, *args) -> bytes:
        return self.hasher.digest(*args)

    def ctx(self):
        return self.hasher.ctx


def get_keccak_writer(sub_writer=None, ctx=None):
    """
    Creates new fresh async Keccak writer
    :param sub_writer:
    :param ctx:
    :return:
    """
    return AHashWriter(
        HashWrapper(crypto.get_keccak() if ctx is None else ctx), sub_writer=sub_writer
    )
