class XmrType:
    VERSION = 0


class UVarintType(XmrType):
    pass


class IntType(XmrType):
    WIDTH = 0
    SIGNED = 0
    VARIABLE = 0

    def __repr__(self):
        return "%s:<w: %s, sig: %s, var: %s>" % (
            self.__class__,
            self.WIDTH,
            self.SIGNED,
            self.VARIABLE,
        )


class BoolType(IntType):
    WIDTH = 1


class UInt8(IntType):
    WIDTH = 1


class Int8(IntType):
    SIGNED = 1
    WIDTH = 1


class UInt16(IntType):
    WIDTH = 2


class Int16(IntType):
    SIGNED = 1
    WIDTH = 2


class UInt32(IntType):
    WIDTH = 4


class Int32(IntType):
    SIGNED = 1
    WIDTH = 4


class UInt64(IntType):
    WIDTH = 8


class SizeT(UInt64):
    WIDTH = 8


class Int64(IntType):
    SIGNED = 1
    WIDTH = 8
