"""
There are two types of monero Ring Confidential Transactions:
1. RCTTypeFull = 1 (used if num_inputs == 1)
2. RCTTypeSimple = 2 (for num_inputs > 1)

There is actually also RCTTypeNull but we ignore that one.
"""
# TODO: to be moved somewhere else


class RctType:
    Full = 1
    Simple = 2
