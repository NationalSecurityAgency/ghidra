'''
Classes corresponding to common Java collection types

These are not ports by any means of the corresponding Java types.
Instead, they just populate the same name space so that exporting need
not map things over. I also use them as convenient places to implement
a common interface.
'''

from java.lang import Object


class Collection(Object):

    @classmethod
    def validate(cls, val, **targs):
        E = cls.resolve_targs(Collection, **targs)['E']
        if not hasattr(val, '__iter__') or not hasattr(val, '__len__'):
            raise ValueError(
                "Value for %s must behave list a collection " +
                "(__iter__ and __len__)")
        for e in val:
            E.validate(e)

    @classmethod
    def subst_targs(cls, E):
        return {}


class List(Collection):

    @classmethod
    def validate(cls, val, **targs):
        E = cls.resolve_targs(List, **targs)['E']
        if not hasattr(val, '__getitem__') or not hasattr(val, '__len__'):
            raise ValueError(
                "Value for %s must behave list a list " +
                "(__getitem__ and __len__)")
        for e in val:
            E.validate(e)

    @classmethod
    def subst_targs(cls, E):
        return dict(E=E)

    @classmethod
    def add_to(cls, l, item):
        l.append(item)


class ArrayList(List):

    @classmethod
    def new(cls):
        return list()
