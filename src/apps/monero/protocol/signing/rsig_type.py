# TODO: to be moved somewhere else
"""
Range signature types

There are four types of range proofs/signatures in official Monero:
 1. RangeProofBorromean = 0
 2. RangeProofBulletproof = 1
 3. RangeProofMultiOutputBulletproof = 2
 4. RangeProofPaddedBulletproof = 3

We simplify all the bulletproofs into one.
"""


class RsigType:
    Borromean = 0
    Bulletproof = 1
