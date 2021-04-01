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
Generic, universal annotations

These correspond directly to those in the Java implementation. In the
Python implementation, the factories and codecs are directly nested in
their annotation classes.
'''

from collections import OrderedDict
from copy import copy
import itertools

from ghidra.comm.packet import (Packet, PacketCodec, PacketDecodeError,
                                bytearray_t, typedesc)
from ghidra.comm.util import BitmaskSet
import java.util


class Annotation:

    def __call__(self, field):
        self.field = field
        field.annotations.insert(0, self)
        return field

    @classmethod
    def findOnField(cls, field):
        for annot in field.annotations:
            if isinstance(annot, cls):
                return annot


class CountedByField(Annotation):

    def __init__(self, value):
        self.by = value

    def get_factory(self):
        annot = self

        class InjectedCounter:

            def get_wrapped_field_codec_for_type(self, pktCls, fld, tdesc,
                                                 codec, chain):
                n = PacketCodec.build_chain_for_type(
                    pktCls, fld, tdesc, codec, chain)

                class counter_field_codec:

                    def encode_field(self, buf, pkt, val):
                        counted_val = pkt._vals[annot.field.name]
                        count = codec.measure_count(counted_val)
                        setattr(pkt, annot.by, count)
                        n.encode_field(buf, pkt, count)

                    def decode_field(self, pkt, buf, count, factory):
                        return n.decode_field(pkt, buf, count, factory)
                return counter_field_codec()

        class Counted:

            def get_wrapped_field_codec_for_type(self, pktCls, fld, tdesc,
                                                 codec, chain):
                codec.inject_chain(
                    pktCls, pktCls._fields_by_name[annot.by],
                    InjectedCounter(), fld, annot)
                n = PacketCodec.build_chain_for_type(
                    pktCls, fld, tdesc, codec, chain)

                class counted_field_codec:

                    def encode_field(self, buf, pkt, val):
                        n.encode_field(buf, pkt, val)

                    def decode_field(self, pkt, buf, count, factory):
                        count = pkt._vals[annot.by]
                        return n.decode_field(pkt, buf, count, factory)
                return counted_field_codec()
        return Counted()


class AbstractSizedBy(Annotation):

    def get_factory(self):
        annot = self

        class InjectedSizer:

            def get_wrapped_field_codec_for_type(self, pktCls, fld, tdesc,
                                                 codec, chain):
                n = PacketCodec.build_chain_for_type(
                    pktCls, fld, tdesc, codec, chain)

                class sizer_field_codec:

                    def encode_field(self, buf, pkt, val):
                        sized_val = pkt._vals[annot.field.name]
                        part = codec.new_encode_buffer()
                        codec.encode_field(part, pkt, annot.field, sized_val)
                        size = codec.measure_encode_size(part)
                        annot.set_size(pkt, size)
                        n.encode_field(buf, pkt, pkt._vals[annot.by])

                    def decode_field(self, pkt, buf, count, factory):
                        return n.decode_field(pkt, buf, count, factory)
                return sizer_field_codec()

        class Sized:

            def get_wrapped_field_codec_for_type(self, pktCls, fld, tdesc,
                                                 codec, chain):
                codec.inject_chain(
                    pktCls, pktCls._fields_by_name[annot.by], InjectedSizer(),
                    fld, annot)
                n = PacketCodec.build_chain_for_type(
                    pktCls, fld, tdesc, codec, chain)

                class sized_field_codec:

                    def encode_field(self, buf, pkt, val):
                        n.encode_field(buf, pkt, val)

                    def decode_field(self, pkt, buf, count, factory):
                        size = annot.get_size(pkt)
                        part = codec.split_buffer(buf, size)
                        ret = n.decode_field(
                            pkt, part, count, factory)
                        if codec.measure_decode_remaining(part) != 0:
                            # TODO: Consider padding
                            raise ValueError("Gratuitous data in sized field")
                        return ret
                return sized_field_codec()
        return Sized()


class SizedByField(AbstractSizedBy):

    def __init__(self, value, adjust=0):
        self.by = value
        self.adjust = adjust

    def set_size(self, pkt, size):
        setattr(pkt, self.by, size - self.adjust)

    def get_size(self, pkt):
        return pkt._vals[self.by] + self.adjust


class SizedByMethods(AbstractSizedBy):

    def __init__(self, getter, setter='', modifies=''):
        self.getter = getter
        self.setter = setter
        self.by = modifies

    def set_size(self, pkt, size):
        getattr(pkt, self.setter)(size)

    def get_size(self, pkt):
        return getattr(pkt, self.getter)()


class TypedByField_TypeSelect:

    def __init__(self, key, type):  # @ReservedAssignment
        self.key = key
        self.tdesc = type


class TypedByField(Annotation):

    def __init__(self, by, map="", types=[]):  # @ReservedAssignment
        self.by = by
        self.map = map
        self.types = types

    def find_accepting_type(self, val):
        for td in self.fwd_map.values():
            try:
                td.validate(val)
                return td.type()
            except Exception:
                pass
        return None

    def get_factory(self):
        annot = self

        class InjectedTyper:

            def get_wrapped_field_codec_for_type(self, pktCls, fld, tdesc,
                                                 codec, chain):
                n = PacketCodec.build_chain_for_type(
                    pktCls, fld, tdesc, codec, chain)

                class typer_field_codec:

                    def encode_field(self, buf, pkt, val):
                        typed_val = pkt._vals[annot.field.name]
                        try:
                            idx = annot.inv_map[typed_val.__class__]
                        except KeyError as e:
                            cls = annot.find_accepting_type(typed_val)
                            if cls is None:
                                raise e
                            idx = annot.inv_map[cls]
                        setattr(pkt, annot.by, idx)
                        n.encode_field(buf, pkt, idx)

                    def decode_field(self, pkt, buf, count, factory):
                        return n.decode_field(pkt, buf, count, factory)
                return typer_field_codec()

        class Typed:

            def get_wrapped_field_codec_for_type(self, pktCls, fld, tdesc,
                                                 codec, chain):
                annot.fwd_map = OrderedDict()
                if annot.map != '':
                    annot.fwd_map.update(getattr(pktCls, annot.map))
                for ts in annot.types:
                    annot.fwd_map[ts.key] = ts.tdesc
                annot.inv_map = OrderedDict()
                nextMap = OrderedDict()
                for k, v in annot.fwd_map.items():
                    t = v.type()
                    annot.inv_map[t] = k
                    if issubclass(t, Packet):
                        codec.register_packet_cls(t)
                    nextMap[t] = PacketCodec.build_chain_for_type(
                        pktCls, fld, v, codec, copy(chain))
                codec.inject_chain(
                    pktCls, pktCls._fields_by_name[annot.by], InjectedTyper(),
                    fld, annot)

                class typed_field_codec:

                    def encode_field(self, buf, pkt, val):
                        try:
                            n = nextMap[val.__class__]
                        except KeyError as e:
                            cls = annot.find_accepting_type(val)
                            if cls is None:
                                raise e
                            n = nextMap[cls]
                        n.encode_field(buf, pkt, val)

                    def decode_field(self, pkt, buf, count, factory):
                        idx = pkt._vals[annot.by]
                        tdesc = annot.fwd_map[idx]
                        n = nextMap[tdesc.type()]
                        return n.decode_field(pkt, buf, count, factory)
                return typed_field_codec()
        return Typed()


class TypedByLookahead(Annotation):

    def __init__(self, value=[]):
        self.types = value

    def get_factory(self):
        annot = self

        class Typed:

            def get_wrapped_field_codec_for_type(self, pktCls, fld, tdesc,
                                                 codec, chain):
                nextMap = OrderedDict()
                for td in annot.types:
                    t = td.type()
                    if issubclass(t, Packet):
                        codec.register_packet_cls(t)
                    nextMap[t] = PacketCodec.build_chain_for_type(
                        pktCls, fld, td, codec, copy(chain))

                class typed_field_codec:

                    def encode_field(self, buf, pkt, val):
                        nextMap[val.__class__].encode_field(buf, pkt, val)

                    def decode_field(self, pkt, buf, count, factory):
                        errs = OrderedDict()
                        backup = codec.backup(buf)
                        for t, n in nextMap.items():
                            try:
                                return n.decode_field(pkt, buf, count, factory)
                            except Exception as e:
                                codec.restore(buf, backup)
                                errs[t] = e.message
                        raise PacketDecodeError(
                            "No selectable lookahead type succeeded " +
                            "for %r: %r" % (
                                fld, errs))
                return typed_field_codec()
        return Typed()


class OptionalField(Annotation):

    def __init__(self):
        pass

    def get_factory(self):
        class Optional:

            def get_wrapped_field_codec_for_type(self, pktCls, fld, tdesc,
                                                 codec, chain):
                n = PacketCodec.build_chain_for_type(
                    pktCls, fld, tdesc, codec, chain)

                class optional_field_codec:

                    def encode_field(self, buf, pkt, val):
                        if val is None:
                            return
                        n.encode_field(buf, pkt, val)

                    def decode_field(self, pkt, buf, count, factory):
                        if codec.measure_decode_remaining(buf) == 0:
                            return None
                        return n.decode_field(pkt, buf, count, factory)
                return optional_field_codec()
        return Optional()


class RepeatedField(Annotation):

    def __init__(self, container=None, elements=None):
        self.container = container
        self.elements = elements

    def get_factory(self):
        annot = self

        class Repeated:

            def get_wrapped_field_codec_for_type(self, pktCls, fld, tdesc,
                                                 codec, chain):
                tdesc = annot.container or tdesc
                if issubclass(tdesc.type(), java.util.Collection):
                    edesc = annot.elements or tdesc.resolve_targs(
                        java.util.Collection)['E']
                else:
                    raise TypeError(
                        "Can't encode using type %r on repeated field" % (
                            tdesc,))
                n = PacketCodec.build_chain_for_type(
                    pktCls, fld, edesc, codec, chain)

                class repeated_field_codec:

                    def encode_field(self, buf, pkt, val):
                        for e in val:
                            n.encode_field(buf, pkt, e)

                    def decode_field(self, pkt, buf, count, factory):
                        it = itertools.count() if count is None else xrange(
                            count)
                        t = tdesc.type()
                        result = factory.new_collection(t)
                        for i in it:  # @UnusedVariable
                            if codec.measure_decode_remaining(buf) == 0:
                                break
                            t.add_to(
                                result,
                                n.decode_field(pkt, buf, None, factory))
                        return result
                return repeated_field_codec()
        return Repeated()


class EncodeChars(Annotation):

    def __init__(self, value):
        self.charset = value

    def get_factory(self):
        annot = self

        class Encoded:

            def get_wrapped_field_codec_for_type(self, pktCls, fld, tdesc,
                                                 codec, chain):
                if not issubclass(tdesc.type(), java.lang.String):
                    return None
                # Test that the charset exists
                ''.encode(self.charset)
                n = PacketCodec.build_chain_for_type(
                    pktCls, fld, bytearray_t, chain)

                class encoded_field_codec:

                    def encode_field(self, buf, pkt, val):
                        n.encode_field(buf, pkt, val.encode(annot.charset))

                    def decode_field(self, pkt, buf, count, factory):
                        return n.decode_field(
                            pkt, buf, count, factory).decode(annot.charset)
                return encoded_field_codec()
        return Encoded()


class BitmaskEncoded(Annotation):

    def __init__(self, universe, type=typedesc(lambda: java.lang.Long)):
        self.universe = universe
        self.type = type

    def get_factory(self):
        annot = self

        class Encoded:

            def get_wrapped_field_codec_for_type(self, pktCls, fld, tdesc, codec, chain):
                if not issubclass(tdesc.type(), BitmaskSet):
                    return None
                n = PacketCodec.build_chain_for_type(
                    pktCls, fld, annot.type, codec, chain)

                class encoded_field_codec:

                    def encode_field(self, buf, pkt, val):
                        n.encode_field(buf, pkt, val.bitmask)

                    def decode_field(self, pkt, buf, count, factory):
                        return BitmaskSet(annot.universe.type(), n.decode_field(pkt, buf, count, factory))
                return encoded_field_codec()
        return Encoded()


class WithFlag_Mode:
    pass


WithFlag_Mode.PRESENT = WithFlag_Mode()
WithFlag_Mode.ABSENT = WithFlag_Mode()


class WithFlag(Annotation):
    def __init__(self, by, flag, mode=WithFlag_Mode.PRESENT):
        self.by = by
        self.flag = flag
        self.mode = mode

    def get_factory(self):
        annot = self

        class InjectedFlags:
            def __init__(self, universe):
                self.universe = universe
                self.flag = getattr(universe, annot.flag)

            def get_wrapped_field_codec_for_type(self, pktCls, fld, tdesc, codec, chain):
                n = PacketCodec.build_chain_for_type(
                    pktCls, fld, tdesc, codec, chain)

                injector = self

                class flags_field_codec:

                    def encode_field(self, buf, pkt, val):
                        flagged_val = pkt._vals[annot.field.name]
                        if val is None:
                            val = BitmaskSet(injector.universe, 0)
                            setattr(pkt, annot.by, val)

                        if (flagged_val is not None) ^ (annot.mode != WithFlag_Mode.PRESENT):
                            val.add(injector.flag)
                        else:
                            val.discard(injector.flag)
                        return n.encode_field(buf, pkt, val)

                    def decode_field(self, buf, pkt, count, factory):
                        return n.decode_field(pkt, buf, count, factory)
                return flags_field_codec()

        class Flagged:

            def get_wrapped_field_codec_for_type(self, pktCls, fld, tdesc, codec, chain):
                byField = pktCls._fields_by_name[annot.by]
                bme = BitmaskEncoded.findOnField(byField)
                universe = bme.universe.type()
                codec.inject_chain(
                    pktCls, byField, InjectedFlags(universe), fld, annot)
                flag = getattr(universe, annot.flag)
                n = PacketCodec.build_chain_for_type(
                    pktCls, fld, tdesc, codec, chain)

                class flagged_field_codec:

                    def encode_field(self, buf, pkt, val):
                        if val is not None:
                            n.encode_field(buf, pkt, val)

                    def decode_field(self, pkt, buf, count, factory):
                        flags = pkt._vals[annot.by]
                        if (flag in flags) ^ (annot.mode != WithFlag_Mode.PRESENT):
                            return n.decode_field(pkt, buf, count, factory)
                        else:
                            return None
                return flagged_field_codec()
        return Flagged()
