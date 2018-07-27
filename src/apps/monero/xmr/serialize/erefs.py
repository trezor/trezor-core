class ElemRefObj:
    def __repr__(self):
        return "RefObj"


class ElemRefArr:
    def __repr__(self):
        return "RefAssoc"


def is_elem_ref(elem_ref):
    """
    Returns true if the elem_ref is an element reference

    :param elem_ref:
    :return:
    """
    return (
        elem_ref
        and isinstance(elem_ref, tuple)
        and len(elem_ref) == 3
        and (elem_ref[0] == ElemRefObj or elem_ref[0] == ElemRefArr)
    )


def has_elem(elem_ref):
    """
    Has element?
    :param elem_ref:
    :return:
    """
    if not is_elem_ref(elem_ref):
        return False
    elif elem_ref[0] == ElemRefObj:
        return hasattr(elem_ref[1], elem_ref[2])
    elif elem_ref[0] == ElemRefArr:
        return elem_ref[2] in elem_ref[1]


def get_elem(elem_ref, default=None):
    """
    Gets the element referenced by elem_ref or returns the elem_ref directly if its not a reference.

    :param elem_ref:
    :param default:
    :return:
    """
    if not is_elem_ref(elem_ref):
        return elem_ref
    elif elem_ref[0] == ElemRefObj:
        return getattr(elem_ref[1], elem_ref[2], default)
    elif elem_ref[0] == ElemRefArr:
        return elem_ref[1][elem_ref[2]]


def set_elem(elem_ref, elem):
    """
    Sets element referenced by the elem_ref. Returns the elem.

    :param elem_ref:
    :param elem:
    :return:
    """
    if elem_ref is None or elem_ref == elem or not is_elem_ref(elem_ref):
        return elem

    elif elem_ref[0] == ElemRefObj:
        setattr(elem_ref[1], elem_ref[2], elem)
        return elem

    elif elem_ref[0] == ElemRefArr:
        elem_ref[1][elem_ref[2]] = elem
        return elem


def eref(obj, key, is_assoc=None):
    """
    Returns element reference
    :param obj:
    :param key:
    :param is_assoc:
    :return:
    """
    if obj is None:
        return None
    if isinstance(key, int) or (is_assoc is not None and is_assoc):
        return ElemRefArr, get_elem(obj), key
    else:
        return ElemRefObj, get_elem(obj), key
