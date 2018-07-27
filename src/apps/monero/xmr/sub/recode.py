from apps.monero.xmr import crypto
from apps.monero.xmr.serialize_messages.tx_ecdh import EcdhTuple


def copy_ecdh(ecdh):
    """
    Clones ECDH tuple
    :param ecdh:
    :return:
    """
    return EcdhTuple(mask=ecdh.mask, amount=ecdh.amount)


def recode_ecdh(ecdh, encode=True):
    """
    In-place ecdhtuple recoding
    :param ecdh:
    :param encode: if true encodes to byte representation, otherwise decodes from byte representation
    :return:
    """
    recode_int = crypto.encodeint if encode else crypto.decodeint
    ecdh.mask = recode_int(ecdh.mask)
    ecdh.amount = recode_int(ecdh.amount)
    return ecdh


def recode_msg(mgs, encode=True):
    """
    Recodes MGs signatures from raw forms to bytearrays so it works with serialization
    :param rv:
    :param encode: if true encodes to byte representation, otherwise decodes from byte representation
    :return:
    """
    recode_int = crypto.encodeint if encode else crypto.decodeint
    recode_point = crypto.encodepoint if encode else crypto.decodepoint

    for idx in range(len(mgs)):
        mgs[idx].cc = recode_int(mgs[idx].cc)
        if hasattr(mgs[idx], "II") and mgs[idx].II:
            for i in range(len(mgs[idx].II)):
                mgs[idx].II[i] = recode_point(mgs[idx].II[i])

        for i in range(len(mgs[idx].ss)):
            for j in range(len(mgs[idx].ss[i])):
                mgs[idx].ss[i][j] = recode_int(mgs[idx].ss[i][j])
    return mgs
