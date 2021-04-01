## ###
#  IP: GHIDRA
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##
'''
A miniature port of the same ghidra.comm.packet library from Java into
Python

This package is necessary to use any packet formats exported by
ghidra.comm.packet.util.pyexport.GeneratePython. Please see its
javadocs for more information and caveats.

Most of the classes here correspond very closely with the same-named
class in the Java implementation, which is the reference
implementation. Please see the javadocs to understand how the pieces
all fit. Unless the correspondence is not obvious, no additional
documentation is provided in the Python port.
'''
from __future__ import print_function

import codecs
import struct
import sys

import java.lang
import java.util


def printargs(func):
    '''
    A debugging annotation to print the arguments and return value
    '''
    def _pa(*args, **kwargs):
        print("before %s: %r, %r" % (func.func_name, args, kwargs))
        result = func(*args, **kwargs)
        print("after %s: %r, %r, %r" % (result, func.func_name, args, kwargs))
        return result
    return _pa


class DefaultPacketFactory:
    '''
    The default packet factory

    Corresponds to the class of the same full name in Java. Python's
    arrays behave like collections, so there is not a ``new_array()``
    method.
    '''

    def register_types(self, codec):
        pass

    def new_collection(self, colCls):
        if colCls == java.util.List:
            return java.util.ArrayList.new()
        else:
            return colCls.new()

    def new_packet(self, pktCls):
        return pktCls()


DEFAULT_FACTORY = DefaultPacketFactory()


class SubstitutingPacketFactory(DefaultPacketFactory):
    '''
    A packet factory that uses a dictionary of substitutions

    Corresponds loosely to ghidra.comm.packet.AbstractPacketFactory
    '''

    def __init__(self, substs):
        self.substs = substs

    def register_types(self, codec):
        for v in self.substs.values():
            codec.register_packet_cls(v)

    def new_packet(self, pktCls):
        if pktCls in self.substs:
            return self.substs[pktCls]()
        return DefaultPacketFactory.new_packet(self, pktCls)


class PacketDecodeError(Exception):
    pass


class field:
    '''
    Loosely corresponds to ghidra.comm.packet.PacketField

    This must also be given information about the declared type of the
    field in Java. Type information is represented using
    :py:class:`typedesc`.

    Because Python does not permit annotating fields, methods must
    be annotated instead. The method should contain no code, other
    than ``pass``, since that code is ignored. The method name
    serves as the field name. For example, to declare a field of
    Java type ``int``::

       @field(typedesc(lambda:java.lang.Integer))
       def f1(self):
           pass

    :param typedesc tdesc: A descriptor of the field's type
    :param default: The default value of the field when constructed
    :param fixed: If final, the constant value of the field
    '''

    _nextIdx = 0

    @classmethod
    def _next_idx(cls):
        '''
        Retrieve and increments a static counter

        This is used to uniquely number every declared field in order
        of declaration. This information is used when encoding and
        decoding fields.

        Note that packet extension is not supported, since packets are
        expected to be exported. Rather than exporting the type tree,
        the exporter should just flatten each packet definition as a
        stand-alone containing all of its fields, including those of
        its super class(es).
        '''

        ret = cls._nextIdx
        cls._nextIdx += 1
        return ret

    def __init__(self, tdesc, default=None, fixed=None):
        self._idx = self._next_idx()
        self.tdesc = tdesc
        self.default = default
        self.fixed = fixed
        self.annotations = []

    def __call__(self, func):
        '''
        Apply the annotation to a placeholder method
        '''

        self.name = func.__name__
        return self

    def __repr__(self):
        if hasattr(self, 'name'):
            return '<field: %s %s>' % (self.tdesc, self.name)
        else:
            return '<unnamed field at 0x%x>' % (id(self),)

    def validate(self, value):
        '''
        Check that the field's value conforms to its declared type
        '''

        if self.fixed is not None:
            raise AttributeError("Field has fixed value")
        self.tdesc.validate(value)

    def build_field_codec(self, pktCls, field, tdesc, codec):
        '''
        Build the field codec chain for this field
        '''

        assert self == field
        return codec.build_field_codec(pktCls, self, tdesc)


class typedesc:
    '''
    A description of a field's type

    Because Python is loosely-typed, and packets are not, some
    information about the declared type of a field ported from Java
    must be carried around. These objects are loosely corresponded to
    Java's own java.lang.reflect.Type. ``field_type`` gives the raw
    class of the described type. This is usually a Python class having
    the same full name as the Java class it corresponds to or holds
    the place of. ``targs`` is a dictionary of whose keys are type
    variable names from the corresponding Java class. Its values are
    other ``typedesc`` objects. For example, a Java ``List<Short>``
    would be described using::

       typedesc(lambda:java.util.List, E=typedesc(lambda:java.lang.Short)))

    Note the use of lambda functions to obtain the actual class
    references. This is unfortunate, but required since Java is a
    compiled language that permits use before declaration. The
    ``typedesc`` is constructed upon declaring the packet class, so
    referring to other packet classes needs to be delayed until all
    declarations have been interpreted.

    :param field_type: corresponds to the raw class for the type
    :param targs: a dictionary of type variable substitutions
    '''

    def __init__(self, field_type, **targs):
        self.type = field_type
        self.targs = targs

    def __repr__(self):
        if len(self.targs) == 0:
            return repr(self.type())
        return '%s<%s>' % (self.type(), ', '.join(
            "%s=%s" % arg
            for arg in self.targs.items()
        ))

    def validate(self, value):
        '''
        Check that a given value conforms to this type
        '''

        self.type().validate(value, **self.targs)

    def encode_binary(self, buf, value):
        '''
        Encode the given value as binary into the given buffer

        Unlike the Java implementation, where encoding and decoding is
        performed strictly by a codec, in Python, the serialization of
        primitives is performed in the ``typedesc``.

        :param bytearray buf: the buffer to append the encoded data to
        :param value: the value to encode
        '''

        # print("encoding into %r, %r as %r" % (buf, value, self.type()))
        self.type().encode_binary(buf, value, **self.targs)

    def decode_binary(self, buf, count):
        '''
        Decode some values of this type from the given buffer

        See :py:method:`encode_binary`
        '''

        return self.type().decode_binary(buf, count, **self.targs)

    def __eq__(self, that):
        return self.type() == that.type() and self.targs == that.targs

    def resolve_targs(self, cls):
        '''
        Compute the type substitutions applied to a given super class

        This returns a dictionary whose keys are type parameter names
        of the given super class. The values are other ``typedesc``
        objects that were substituted in the course of describing this
        type from the perspective of that superclass. For example, the
        type description corresponding to ``List<Integer>`` would
        return the dictionary ``{'E': java.lang.Integer}`` for a call
        to ``resolve_targs(java.util.Collection)``.

        :param cls: A Python super class of this description's raw type
        :return: a dictionary of type parameters substitutions
        '''

        if cls == self.type:
            return self.targs
        return self.type().resolve_targs(cls, **self.targs)


bytearray_t = typedesc(
    lambda: java.util.List, E=typedesc(lambda: java.lang.Byte))


class BinaryBuffer:
    '''
    A wrapper around Python's ``bytearray`` to behave more like
    java.nio.ByteBuffer.
    '''

    def __init__(self, buf=''):
        self.buf = bytearray(buf)
        self._order = '>'
        self.dec = codecs.lookup('UTF-8').incrementaldecoder()

    def __repr__(self):
        return 'BinaryBuffer_%x(%r)' % (id(self), self.buf,)

    def order(self, order=None):
        ret = self._order
        self._order = order or self._order
        return ret

    def put_Struct(self, val, s):
        '''
        Encode a binary value using a given ``struct`` format string
        '''

        s = struct.Struct(self._order + s)
        self.buf.extend(s.pack(val))

    def get_Struct(self, s):
        '''
        Decode a binary value using a given ``struct`` format string
        '''

        s = struct.Struct(self._order + s)
        part, self.buf[:] = bytes(self.buf[:s.size]), self.buf[s.size:]
        return s.unpack(part)[0]

    def put_Boolean(self, val):
        self.buf.append(1 if val else 0)

    def get_Boolean(self):
        ret, self.buf[:] = self.buf[0], self.buf[1:]
        return ret != 0

    def put_Character(self, val):
        charset = 'UTF-16-BE' if self._order == '>' else 'UTF-16-LE'
        self.buf.extend(val.encode(charset))

    def get_Character(self):
        charset = 'UTF-16-BE' if self._order == '>' else 'UTF-16-LE'
        ret, self.buf[:] = self.buf[:2].decode(charset), self.buf[2:]
        return ret

    def put_String(self, val):
        self.buf.extend(val.encode('UTF-8'))

    def get_String(self, count):
        if count is None:
            ret = str(self.buf)
            self.buf[:] = ''
            return ret
        else:
            self.dec.reset()
            result = ''
            while len(self.buf) > 0 and len(result) < count:
                n, self.buf[:] = self.buf[:1], self.buf[1:]
                result += self.dec.decode(n)
            return result


class PacketCodec:

    def __init__(self):
        self.chains = {}
        self.codecs = {}
        self.registry = set()

    def decode_and_store_field(self, pkt, fld, buf, factory):
        if fld.fixed is not None:
            count = self.measure_count(fld.fixed)
        else:
            count = None
        val = self.decode_field(pkt, fld, buf, count, factory)
        if fld.fixed is not None:
            if val != fld.fixed:
                raise PacketDecodeError(
                    "Fixed value mismatch for %s (%r != %r)" % (
                        fld.name, fld.fixed, val))
        else:
            setattr(pkt, fld.name, val)

    def decode_field(self, pkt, fld, buf, count, factory):
        codec = self.codecs[pkt.__class__, fld.name]
        return codec.decode_field(pkt, buf, count, factory)

    def decode_packet(self, pktCls, data, factory=DEFAULT_FACTORY):
        if pktCls not in self.registry:
            raise TypeError("Cannot decode unregistered packet type: %r" % (
                pktCls,))
        buf = self.new_decode_buffer(data)
        result = self._decode_packet(None, None, buf, pktCls, factory)
        if self.measure_decode_remaining(buf) != 0:
            raise PacketDecodeError(
                "Packet did not consume given buffer: %r" % (
                    buf,))
        return result

    def _decode_packet(self, parent, fld, buf, pktCls, factory):
        val = factory.new_packet(pktCls)
        if val.__class__ not in self.registry:
            raise TypeError(
                "Decoding %r: constructed type %r is not " +
                "registered with this codec" % (
                    fld, val.__class__))
        val.parent = parent
        for f in val._fields:
            self.decode_and_store_field(val, f, buf, factory)
        return val

    def encode_field(self, buf, pkt, fld, val):
        codec = self.codecs[pkt.__class__, fld.name]
        codec.encode_field(buf, pkt, val)

    def encode_packet(self,  val, buf=None, fld=None):
        pktCls = val.__class__
        if pktCls not in self.registry:
            if fld is None:
                raise TypeError(
                    "Cannot encode unregistered packet type: %r" % (
                        pktCls,))
            else:
                raise TypeError(
                    "Field %r has value of an unregistered type: %r" % (
                        fld, pktCls,))
        if buf is None:
            buf = self.new_encode_buffer()
        for f in val._fields:
            self.encode_field(buf, val, f, f.fixed or val._vals[f.name])
        return self.finish_encode(buf)

    def get_factory_for_annotation(self, pktCls, fld, annot):
        if hasattr(annot, 'get_factory'):
            return annot.get_factory()
        else:
            # Ignore the annotation
            return None

    def get_field_codec_for_type(self, pktCls, fld, tdesc):
        t = tdesc.type()
        if issubclass(t, Packet):
            codec = self
            self.register_packet_cls(t)

            class packet_field_codec:

                def encode_field(self, buf, pkt, val):
                    codec.encode_packet(val, buf, fld)

                def decode_field(self, pkt, buf, count, factory):
                    return codec._decode_packet(pkt, fld, buf, t, factory)
            return packet_field_codec()
        return None

    def inject_chain(self, pktCls, tfld, wrapper, afld, annot):
        if pktCls._fields.index(afld) <= pktCls._fields.index(tfld):
            raise ValueError(
                "Referenced field %r must precede annotated field %r" % (
                    tfld, afld))
        self.chains[pktCls, tfld.name].insert(0, wrapper)

    def measure_count(self, obj):
        return len(obj)

    def measure_encode_size(self, buf):
        return len(buf.buf)

    def register_field(self, pktCls, fld, allFlds):
        chain = [self]
        for annot in fld.annotations:
            factory = self.get_factory_for_annotation(pktCls, fld, annot)
            if factory is None:
                continue
            chain.insert(0, factory)
        self.chains[pktCls, fld.name] = chain

    def register_packet_cls(self, pktCls):
        if pktCls in self.registry:
            return  # Avoid infinite recursion
        self.registry.add(pktCls)
        for fld in pktCls._fields:
            self.register_field(pktCls, fld, pktCls._fields)
        for fld in reversed(pktCls._fields):
            chain = self.chains[pktCls, fld.name]
            codec = self.build_chain_for_type(
                pktCls, fld, fld.tdesc, self, chain)
            self.codecs[pktCls, fld.name] = codec

    def split_buffer(self, buf, at):
        ret = buf.buf[:at]
        buf.buf[:at] = ''
        return BinaryBuffer(ret)

    @classmethod
    def build_chain_for_type(cls, pktCls, fld, tdesc, codec, chain):
        n = chain.pop(0)
        if len(chain) != 0:
            temp = n.get_wrapped_field_codec_for_type(
                pktCls, fld, tdesc, codec, chain)
        else:
            temp = n.get_field_codec_for_type(pktCls, fld, tdesc)
        if temp is None:
            raise TypeError(
                "Codec or wrapper %r cannot provide encoder for %r" % (
                    n, tdesc))
        return temp


def make_property(name, fld):
    '''
    A property to control access to each field of a packet

    Used by the packet meta class, each field property ensures that the
    assigned value conforms to the field's described type. The actual
    values are kept in a separate dictionary that the packet codec can
    access directly.
    '''

    @property
    def _prop(self):
        return self._vals[name]

    @_prop.setter  # NOTE: This should have the same name as the getter
    def _prop(self, value):
        fld.validate(value)
        self._vals[name] = value

    # NOTE: If the setter name is different, it's name must go here instead
    return _prop


class PacketMeta(type):
    '''
    A meta class for packets

    This meta class installs a property for each field, replacing the
    annotated method.
    '''

    def __new__(self, classname, bases, classdict):
        fields = []
        fields_by_name = {}
        for name, fld in classdict.items():
            if isinstance(fld, field):
                fields.append(fld)
                fields_by_name[name] = fld
                classdict[name] = make_property(name, fld)
            fields.sort(key=lambda f: f._idx)
            classdict['_fields'] = tuple(fields)
            classdict['_fields_by_name'] = fields_by_name

        cls = type.__new__(self, classname, bases, classdict)
        return cls


class Packet:
    '''
    A packet

    All packet types are subclasses of ``Packet`` just as in the Java
    implementation. Please see the :py:class:`field` annotation
    regarding how to declare fields.

    Unlike the Java implementation, subclasses of other packet types is
    not supported. Instead, each packet type should be based directly
    on ``Packet``, and all fields, including those of its super classes
    in Java, should be declared. The
    ghidra.comm.util.pyexport.GeneratePython utility will do that
    already.
    '''

    __metaclass__ = PacketMeta

    def __init__(self, *args, **kwargs):
        self._vals = {}
        if len(args) != 0:
            if len(kwargs) != 0:
                raise ValueError(
                    "%s: Cannot give positional arguments and keyword " +
                    "arguments" % (
                        self.__class__.__name__))
            i = iter(args)
            for fld in self._fields:
                if fld.fixed is None:
                    try:
                        val = i.next()
                        setattr(self, fld.name, val)
                    except StopIteration:
                        raise ValueError(
                            "Not enough positional arguments given")
            try:
                i.next()
                raise ValueError("Too many positional arguments given")
            except StopIteration:
                pass
        else:
            s = set(kwargs) - set(self._fields_by_name)
            if len(s) > 0:
                raise ValueError(
                    "%s: Gave invalid keyword arguments: %s" % (
                        self.__class__.__name__, ','.join(s)))
            for fld in self._fields:
                self._vals[fld.name] = fld.fixed or fld.default
                if fld.name in kwargs:
                    setattr(self, fld.name, kwargs[fld.name])

    @classmethod
    def validate(cls, value):
        '''
        Check that the given value is an instance of this packet type
        '''

        if not isinstance(value, cls):
            raise ValueError("Must be an instance of %s" % cls.__name__)

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, ','.join(
            '%s=%r' % (fld.name, self._vals[fld.name])
            for fld in self._fields
            if fld.fixed is None
        ))

    def __cmp__(self, that):
        result = cmp(self.__class__, that.__class__)
        if result != 0:
            return result
        for fld in self._fields:
            if fld.fixed is not None:
                continue
            result = cmp(self._vals[fld.name], that._vals[fld.name])
            if result != 0:
                return result
        return 0

    def __hash__(self):
        parts = []
        parts.append(self.__class__)
        for fld in self._fields:
            if fld.fixed is not None:
                continue
            parts.append(self._vals[fld.name])
        return hash(tuple(parts))
