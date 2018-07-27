from micropython import const


class TState(object):
    """
    Transaction state
    """

    START = const(0)
    INIT = const(1)
    INP_CNT = const(2)
    INPUT = const(3)
    INPUT_DONE = const(4)
    INPUT_PERM = const(5)
    INPUT_VINS = const(6)
    OUTPUT = const(7)
    OUTPUT_DONE = const(8)
    FINAL_MESSAGE = const(9)
    SIGNATURE = const(10)
    SIGNATURE_DONE = const(11)
    FINAL = const(12)
    FAIL = const(250)

    def __init__(self):
        self.s = self.START
        self.in_mem = False

    def state_save(self):
        return self.s, self.in_mem

    def state_load(self, x):
        self.s, self.in_mem = x

    def init_tsx(self):
        if self.s != self.START:
            raise ValueError("Illegal state")
        self.s = self.INIT

    def inp_cnt(self, in_mem):
        if self.s != self.INIT:
            raise ValueError("Illegal state")
        self.s = self.INP_CNT
        self.in_mem = in_mem

    def input(self):
        if self.s != self.INP_CNT and self.s != self.INPUT:
            raise ValueError("Illegal state")
        self.s = self.INPUT

    def input_done(self):
        if self.s != self.INPUT:
            raise ValueError("Illegal state")
        self.s = self.INPUT_DONE

    def input_permutation(self):
        if self.s != self.INPUT_DONE:
            raise ValueError("Illegal state")
        self.s = self.INPUT_PERM

    def input_vins(self):
        if self.s != self.INPUT_PERM and self.s != self.INPUT_VINS:
            raise ValueError("Illegal state")
        self.s = self.INPUT_VINS

    def is_input_vins(self):
        return self.s == self.INPUT_VINS

    def set_output(self):
        if (
            (not self.in_mem and self.s != self.INPUT_VINS)
            or (self.in_mem and self.s != self.INPUT_PERM)
        ) and self.s != self.OUTPUT:
            raise ValueError("Illegal state")
        self.s = self.OUTPUT

    def set_output_done(self):
        if self.s != self.OUTPUT:
            raise ValueError("Illegal state")
        self.s = self.OUTPUT_DONE

    def set_final_message_done(self):
        if self.s != self.OUTPUT_DONE:
            raise ValueError("Illegal state")
        self.s = self.FINAL_MESSAGE

    def set_signature(self):
        if self.s != self.FINAL_MESSAGE and self.s != self.SIGNATURE:
            raise ValueError("Illegal state")
        self.s = self.SIGNATURE

    def set_signature_done(self):
        if self.s != self.SIGNATURE:
            raise ValueError("Illegal state")
        self.s = self.SIGNATURE_DONE

    def set_final(self):
        if self.s != self.SIGNATURE_DONE:
            raise ValueError("Illegal state")
        self.s = self.FINAL

    def set_fail(self):
        self.s = self.FAIL

    def is_terminal(self):
        return self.s in [self.FINAL, self.FAIL]
