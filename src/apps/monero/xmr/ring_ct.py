# Author: https://github.com/monero-project/mininero
# Author: Dusan Klinec, ph4r05, 2018

import gc

from apps.monero.xmr import crypto


def prove_range_bp(amount, last_mask=None):
    mask = last_mask if last_mask is not None else crypto.random_scalar()
    bp_proof = prove_range_bp_batch([amount], [mask])

    C = crypto.decodepoint(bp_proof.V[0])
    C = crypto.point_mul8(C)

    gc.collect()

    # Return as struct as the hash(BP_struct) != hash(BP_serialized)
    # as the original hashing does not take vector lengths into account which are dynamic
    # in the serialization scheme (and thus extraneous)
    return C, mask, bp_proof


def prove_range_bp_batch(amounts, masks):
    from apps.monero.xmr import bulletproof as bp

    bpi = bp.BulletProofBuilder()
    bp_proof = bpi.prove_batch([crypto.sc_init(a) for a in amounts], masks)
    del (bpi, bp)
    gc.collect()

    return bp_proof


def verify_bp(bp_proof, amounts=None, masks=None):
    from apps.monero.xmr import bulletproof as bp

    if amounts:
        bp_proof.V = []
        for i in range(len(amounts)):
            C = crypto.gen_commitment(masks[i], amounts[i])
            crypto.scalarmult_into(C, C, crypto.sc_inv_eight())
            bp_proof.V.append(crypto.encodepoint(C))

    bpi = bp.BulletProofBuilder()
    res = bpi.verify(bp_proof)
    gc.collect()

    # Return as struct as the hash(BP_struct) != hash(BP_serialized)
    # as the original hashing does not take vector lengths into account which are dynamic
    # in the serialization scheme (and thus extraneous)
    return res


def prove_range_chunked(amount, last_mask=None):
    # The large chunks allocated first to avoid potential memory fragmentation issues.
    ai = bytearray(32 * 64)
    alphai = bytearray(32 * 64)
    Cis = bytearray(32 * 64)
    s0s = bytearray(32 * 64)
    s1s = bytearray(32 * 64)
    buff = bytearray(32)
    ee_bin = bytearray(32)

    a = crypto.sc_init(0)
    si = crypto.sc_init(0)
    c = crypto.sc_init(0)
    ee = crypto.sc_init(0)
    tmp_ai = crypto.sc_init(0)
    tmp_alpha = crypto.sc_init(0)

    C_acc = crypto.identity()
    C_h = crypto.xmr_H()
    C_tmp = crypto.identity()
    L = crypto.identity()
    Zero = crypto.identity()
    kck = crypto.get_keccak()

    for ii in range(64):
        crypto.random_scalar(tmp_ai)
        if last_mask is not None and ii == 63:
            crypto.sc_sub_into(tmp_ai, last_mask, a)

        crypto.sc_add_into(a, a, tmp_ai)
        crypto.random_scalar(tmp_alpha)

        crypto.scalarmult_base_into(L, tmp_alpha)
        crypto.scalarmult_base_into(C_tmp, tmp_ai)

        # C_tmp += &Zero if BB(ii) == 0 else &C_h
        crypto.point_add_into(C_tmp, C_tmp, Zero if ((amount >> ii) & 1) == 0 else C_h)
        crypto.point_add_into(C_acc, C_acc, C_tmp)

        # Set Ci[ii] to sigs
        crypto.encodepoint_into(Cis, C_tmp, ii << 5)
        crypto.encodeint_into(ai, tmp_ai, ii << 5)
        crypto.encodeint_into(alphai, tmp_alpha, ii << 5)

        if ((amount >> ii) & 1) == 0:
            crypto.random_scalar(si)
            crypto.encodepoint_into(buff, L)
            crypto.hash_to_scalar_into(c, buff)

            crypto.point_sub_into(C_tmp, C_tmp, C_h)
            crypto.add_keys2_into(L, si, c, C_tmp)

            crypto.encodeint_into(s1s, si, ii << 5)

        crypto.encodepoint_into(buff, L)
        kck.update(buff)

        crypto.point_double_into(C_h, C_h)

    # Compute ee
    tmp_ee = kck.digest()
    crypto.decodeint_into(ee, tmp_ee)
    del (tmp_ee, kck)

    C_h = crypto.xmr_H()
    gc.collect()

    # Second pass, s0, s1
    for ii in range(64):
        crypto.decodeint_into(tmp_alpha, alphai, ii << 5)
        crypto.decodeint_into(tmp_ai, ai, ii << 5)

        if ((amount >> ii) & 1) == 0:
            crypto.sc_mulsub_into(si, tmp_ai, ee, tmp_alpha)
            crypto.encodeint_into(s0s, si, ii << 5)

        else:
            crypto.random_scalar(si)
            crypto.encodeint_into(s0s, si, ii << 5)

            crypto.decodepoint_into(C_tmp, Cis, ii << 5)
            crypto.add_keys2_into(L, si, ee, C_tmp)
            crypto.encodepoint_into(buff, L)
            crypto.hash_to_scalar_into(c, buff)

            crypto.sc_mulsub_into(si, tmp_ai, c, tmp_alpha)
            crypto.encodeint_into(s1s, si, ii << 5)

        crypto.point_double_into(C_h, C_h)

    crypto.encodeint_into(ee_bin, ee)

    del (ai, alphai, buff, tmp_ai, tmp_alpha, si, c, ee, C_tmp, C_h, L, Zero)
    gc.collect()

    return C_acc, a, [s0s, s1s, ee_bin, Cis]


# Ring-ct MG sigs
# Prove:
#   c.f. http:#eprint.iacr.org/2015/1098 section 4. definition 10.
#   This does the MG sig on the "dest" part of the given key matrix, and
#   the last row is the sum of input commitments from that column - sum output commitments
#   this shows that sum inputs = sum outputs
# Ver:
#   verifies the above sig is created corretly


#
# Key image import / export
#


def generate_ring_signature(prefix_hash, image, pubs, sec, sec_idx, test=False):
    """
    Generates ring signature with key image.
    void crypto_ops::generate_ring_signature()
    """
    from trezor.utils import memcpy

    if test:
        from apps.monero.xmr import monero

        t = crypto.scalarmult_base(sec)
        if not crypto.point_eq(t, pubs[sec_idx]):
            raise ValueError("Invalid sec key")

        k_i = monero.generate_key_image(crypto.encodepoint(pubs[sec_idx]), sec)
        if not crypto.point_eq(k_i, image):
            raise ValueError("Key image invalid")
        for k in pubs:
            crypto.ge_frombytes_vartime_check(k)

    buff_off = len(prefix_hash)
    buff = bytearray(buff_off + 2 * 32 * len(pubs))
    memcpy(buff, 0, prefix_hash, 0, buff_off)
    mvbuff = memoryview(buff)

    sum = crypto.sc_0()
    k = crypto.sc_0()
    sig = []
    for i in range(len(pubs)):
        sig.append([crypto.sc_0(), crypto.sc_0()])  # c, r

    for i in range(len(pubs)):
        if i == sec_idx:
            k = crypto.random_scalar()
            tmp3 = crypto.scalarmult_base(k)
            crypto.encodepoint_into(mvbuff[buff_off : buff_off + 32], tmp3)
            buff_off += 32

            tmp3 = crypto.hash_to_point(crypto.encodepoint(pubs[i]))
            tmp2 = crypto.scalarmult(tmp3, k)
            crypto.encodepoint_into(mvbuff[buff_off : buff_off + 32], tmp2)
            buff_off += 32

        else:
            sig[i] = [crypto.random_scalar(), crypto.random_scalar()]
            tmp3 = pubs[i]
            tmp2 = crypto.ge25519_double_scalarmult_base_vartime(
                sig[i][0], tmp3, sig[i][1]
            )
            crypto.encodepoint_into(mvbuff[buff_off : buff_off + 32], tmp2)
            buff_off += 32

            tmp3 = crypto.hash_to_point(crypto.encodepoint(tmp3))
            tmp2 = crypto.ge25519_double_scalarmult_vartime2(
                sig[i][1], tmp3, sig[i][0], image
            )
            crypto.encodepoint_into(mvbuff[buff_off : buff_off + 32], tmp2)
            buff_off += 32

            sum = crypto.sc_add(sum, sig[i][0])

    h = crypto.hash_to_scalar(buff)
    sig[sec_idx][0] = crypto.sc_sub(h, sum)
    sig[sec_idx][1] = crypto.sc_mulsub(sig[sec_idx][0], sec, k)
    return sig


def export_key_image(
    creds, subaddresses, pkey, tx_pub_key, additional_tx_pub_keys, out_idx, test=True
):
    """
    Generates key image for the TXO + signature for the key image
    """
    from apps.monero.xmr import monero

    r = monero.generate_tx_spend_and_key_image_and_derivation(
        creds, subaddresses, pkey, tx_pub_key, additional_tx_pub_keys, out_idx
    )
    xi, ki, recv_derivation = r[:3]

    phash = crypto.encodepoint(ki)
    sig = generate_ring_signature(phash, ki, [pkey], xi, 0, test)

    return ki, sig
