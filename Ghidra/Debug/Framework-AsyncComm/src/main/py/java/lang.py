'''
Classes corresponding to common Java types

These are not by any means ports of the corresponding Java types.
Instead, they just populate the same name space so that exporting need
not map things over. They also contain binary encoding and decoding
logic.
'''


class ObjectMeta(type):

    def __repr__(self):
        return self.__module__ + '.' + self.__name__

    def __new__(self, classname, bases, classdict):
        if len(bases) == 1:
            classdict['sup'] = bases[0]
        elif classname == 'Object':
            pass
        else:
            raise TypeError("Too many bases for %s: %r" % (classname, bases,))
        return type.__new__(self, classname, bases, classdict)


class Object:
    __metaclass__ = ObjectMeta

    @classmethod
    def validate(cls, val):
        pass

    @classmethod
    def encode_binary(cls, buf, val):
        raise ValueError("Cannot encode as %r" % (cls,))

    @classmethod
    def decode_binary(cls, buf, count):
        raise ValueError("Cannot decode as %r" % (cls,))

    @classmethod
    def subst_targs(cls):
        return {}

    @classmethod
    def resolve_targs(cls, sup, **targs):
        cur = cls
        while cur != sup:
            if cur == Object:
                raise ValueError(
                    "%r is not in the hierarchy of %r" % (sup, cls))
            targs = cur.subst_targs(**targs)
            cur = cur.sup
        return targs


class Number(Object):

    @classmethod
    def validate(cls, val):
        if val is None:
            return
        elif not isinstance(val, (int, long, float)):
            raise TypeError(
                "Value for %s for be numeric. Got %r" % (cls.__name__, val))

    @classmethod
    def encode_binary(cls, buf, val):
        buf.put_Struct(val, cls.struct)

    @classmethod
    def decode_binary(cls, buf, count):
        return buf.get_Struct(cls.struct)


class IntegralNumber(Number):

    @classmethod
    def validate(cls, val):
        if val is None:
            return
        elif not isinstance(val, (int, long)):
            raise TypeError(
                "Value for %s must be integral. Got %r" % (cls.__name__, val))
        elif not cls.min <= val < cls.max:
            raise ValueError("Value for %s must be in [%s, %s). Got %r" % (
                cls.__name__, cls.min, cls.max, val))


class Boolean(Object):

    @classmethod
    def validate(cls, val):
        if val is None:
            return
        elif not isinstance(val, bool):
            raise TypeError(
                "Value for %s must be boolean. Got %r" % (cls.__name__, val))

    @classmethod
    def encode_binary(cls, buf, val):
        buf.put_Boolean(val)

    @classmethod
    def decode_binary(cls, buf, count):
        return buf.get_Boolean()


class Byte(IntegralNumber):
    min = -0x80
    max = 0x80
    struct = 'b'


class Character(Object):

    @classmethod
    def validate(cls, val):
        if val is None:
            return
        elif not isinstance(val, (str, unicode)) or not len(val) == 1:
            raise ValueError(
                "Value for %r must be a string of length 1. Got %r" % (
                    cls.__name__, val))

    @classmethod
    def encode_binary(cls, buf, val):
        buf.put_Character(val)

    @classmethod
    def decode_binary(cls, buf, count):
        return buf.get_Character()


class Short(IntegralNumber):
    min = -0x8000
    max = 0x8000
    struct = 'h'


class Integer(IntegralNumber):
    min = -0x80000000
    max = 0x80000000
    struct = 'i'


class Long(IntegralNumber):
    min = -0x8000000000000000
    max = 0x8000000000000000
    struct = 'q'


class Float(Number):
    struct = 'f'


class Double(Number):
    struct = 'd'


class Enum(Object):
    def __repr__(self):
        return self.name

    @classmethod
    def validate(cls, val):
        if val is None:
            return
        elif not isinstance(val, cls):
            raise ValueError("Value must be from the enumeration %r" % (cls,))

    @classmethod
    def encode_binary(cls, buf, val):
        if len(cls.values) < 0x100:
            buf.put_Struct(val.ordinal, 'B')
        elif len(cls.values) < 0x10000:
            buf.put_Struct(val.ordinal, 'H')
        elif len(cls.values) < 0x100000000:
            buf.put_Struct(val.ordinal, 'I')
        else:
            buf.put_Struct(val.ordinal, 'Q')

    @classmethod
    def decode_binary(cls, buf, count):
        if len(cls.values) < 0x100:
            return cls.values[buf.get_Struct('B')]
        elif len(cls.values) < 0x10000:
            return cls.values[buf.get_Struct('H')]
        elif len(cls.vaules) < 0x100000000:
            return cls.values[buf.get_Struct('I')]
        else:
            return cls.values[buf.get_Struct('Q')]


class String(Object):

    @classmethod
    def validate(cls, val):
        if val is None:
            return
        elif not isinstance(val, (str, unicode)):
            raise ValueError("Value must be a string")

    @classmethod
    def encode_binary(cls, buf, val):
        buf.put_String(val)

    @classmethod
    def decode_binary(cls, buf, count):
        return buf.get_String(count)
