from apps.monero.xmr.serialize.base_types import XmrType
from apps.monero.xmr.serialize.obj_helper import eq_obj_contents, is_type, slot_obj_dict


class BlobType(XmrType):
    """
    Binary data

    Represented as bytearray() or a list of values in data structures.
    Not wrapped in the BlobType, the BlobType is only a scheme descriptor.
    Behaves in the same way as primitive types

    Supports also the wrapped version (__init__, DATA_ATTR, eq, repr...),
    """

    DATA_ATTR = "data"
    FIX_SIZE = 0
    SIZE = 0

    def __eq__(self, rhs):
        return eq_obj_contents(self, rhs)

    def __repr__(self):
        dct = slot_obj_dict(self) if hasattr(self, "__slots__") else self.__dict__
        return "<%s: %s>" % (self.__class__.__name__, dct)


class UnicodeType(XmrType):
    pass


class VariantType(XmrType):
    """
    Union of types, variant tags needed. is only one of the types. List in typedef, enum.
    Wraps the variant type in order to unambiguously support variant of variants.
    Supports also unwrapped value using type system to distinguish variants - simplifies the construction.
    """

    WRAPS_VALUE = False

    def __init__(self):
        self.variant_elem = None
        self.variant_elem_type = None

    @classmethod
    def f_specs(cls):
        return ()

    def set_variant(self, fname, fvalue):
        self.variant_elem = fname
        self.variant_elem_type = fvalue.__class__
        setattr(self, fname, fvalue)

    def __eq__(self, rhs):
        return eq_obj_contents(self, rhs)

    def __repr__(self):
        dct = slot_obj_dict(self) if hasattr(self, "__slots__") else self.__dict__
        return "<%s: %s>" % (self.__class__.__name__, dct)


class ContainerType(XmrType):
    """
    Array of elements
    Represented as a real array in the data structures, not wrapped in the ContainerType.
    The Container type is used only as a schema descriptor for serialization.
    """

    FIX_SIZE = 0
    SIZE = 0
    ELEM_TYPE = None


class TupleType(XmrType):
    @classmethod
    def f_specs(cls):
        return ()


class MessageType(XmrType):
    def __init__(self, **kwargs):
        for kw in kwargs:
            setattr(self, kw, kwargs[kw])

    def __eq__(self, rhs):
        return eq_obj_contents(self, rhs)

    def __repr__(self):
        dct = slot_obj_dict(self) if hasattr(self, "__slots__") else self.__dict__
        return "<%s: %s>" % (self.__class__.__name__, dct)

    @classmethod
    def f_specs(cls):
        return ()

    def _field(self, fname=None, idx=None):
        fld = None
        specs = self.f_specs()
        if fname is not None:
            fld = [x for x in specs if x[0] == fname][0]
        elif idx is not None:
            fld = specs[idx]
        return fld

    async def _msg_field(self, ar, fname=None, idx=None, **kwargs):
        return await ar.message_field(self, self._field(fname=fname, idx=idx), **kwargs)


def container_elem_type(container_type, params):
    """
    Returns container element type

    :param container_type:
    :param params:
    :return:
    """
    elem_type = params[0] if params else None
    if elem_type is None:
        elem_type = container_type.ELEM_TYPE
    return elem_type


def gen_elem_array(size, elem_type=None):
    """
    Generates element array of given size and initializes with given type.
    Supports container type, used for pre-allocation before deserialization.
    :param size:
    :param elem_type:
    :return:
    """
    if elem_type is None or not callable(elem_type):
        return [elem_type] * size
    if is_type(elem_type, ContainerType):

        def elem_type():
            return []

    res = []
    for _ in range(size):
        res.append(elem_type())
    return res
