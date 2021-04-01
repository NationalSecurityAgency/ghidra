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
The binary packet codec and supporting objects

This also contains annotations particular to the binary packet codec.
Those are implemented via classes nested in the codec itself.
'''

from __future__ import print_function

from ghidra.comm.packet import (BinaryBuffer, PacketDecodeError, Packet,
                                PacketCodec, bytearray_t)

from .annot import Annotation


class BinaryPacketCodec(PacketCodec):
    '''
    The binary packet codec

    This encodes to Python ``bytes`` objects, using ``bytearray`` as
    the temporary buffers. Also, because the encoding and decoding to
    binary is implemented in the types themselves, this codec simply
    delegates to those routines.
    '''

    def finish_encode(self, buf):
        return bytes(buf.buf)

    def get_factory_for_annotation(self, pktCls, fld, annot):
        if isinstance(annot, SequenceTerminated):
            class Terminated:

                def get_wrapped_field_codec_for_type(self, pktCls, fld, tdesc,
                                                     codec, chain):
                    n = PacketCodec.build_chain_for_type(
                        pktCls, fld, tdesc, codec, chain)

                    class terminated_field_codec:

                        def encode_field(self, buf, pkt, val):
                            n.encode_field(buf, pkt, val)
                            if annot.cond != '':
                                if getattr(pkt, annot.cond) is None:
                                    return
                            buf.buf.extend(annot.tok)

                        def decode_field(self, pkt, buf, count, factory):
                            i = buf.buf.find(annot.tok)
                            if i == -1:
                                if annot.cond != '':
                                    return n.decode_field(pkt, buf, count,
                                                          factory)
                                elif len(buf.buf) == 0:
                                    raise PacketDecodeError("Buffer is empty")
                                else:
                                    raise PacketDecodeError(
                                        "Missing terminator sequence %r" % (
                                            annot.tok))
                            part = BinaryBuffer(buf.buf[:i])
                            buf.buf[:] = buf.buf[i + len(annot.tok):]
                            ret = n.decode_field(pkt, part, count, factory)
                            return ret
                    return terminated_field_codec()
            return Terminated()
        elif isinstance(annot, ReverseByteOrder):
            class Reversed:

                def get_wrapped_field_codec_for_type(self, pktCls, fld, tdesc,
                                                     codec, chain):
                    n = PacketCodec.build_chain_for_type(
                        pktCls, fld, tdesc, codec, chain)

                    class byte_reversed_field_codec:

                        def encode_field(self, buf, pkt, val):
                            orig = buf.order()
                            buf.order('<' if orig == '>' else '>')
                            n.encode_field(buf, pkt, val)
                            buf.order(orig)

                        def decode_field(self, pkt, buf, count, factory):
                            orig = buf.order()
                            buf.order('<' if orig == '>' else '>')
                            ret = n.decode_field(pkt, buf, count, factory)
                            buf.order(orig)
                            return ret
                    return byte_reversed_field_codec()
            return Reversed()
        return PacketCodec.get_factory_for_annotation(self, pktCls, fld, annot)

    def get_field_codec_for_type(self, pktCls, fld, tdesc):
        if issubclass(tdesc.type(), Packet):
            return PacketCodec.get_field_codec_for_type(self, pktCls, fld,
                                                        tdesc)
        elif tdesc == bytearray_t:
            class bytearray_field_codec:

                def encode_field(self, buf, pkt, val):
                    buf.buf.extend(val)

                def decode_field(self, pkt, buf, count, factory):
                    ret = bytearray(buf.buf)
                    buf.buf[:] = ''
                    return ret
            return bytearray_field_codec()
        else:
            class field_codec:

                def encode_field(self, buf, pkt, val):
                    tdesc.encode_binary(buf, val)

                def decode_field(self, pkt, buf, count, factory):
                    return tdesc.decode_binary(buf, count)
            return field_codec()

    def measure_decode_remaining(self, buf):
        return len(buf.buf)

    def new_decode_buffer(self, data):
        return BinaryBuffer(data)

    def new_encode_buffer(self):
        return BinaryBuffer()

    def backup(self, buf):
        return bytearray(buf.buf)

    def restore(self, buf, backup):
        buf.buf[:] = backup


class BinaryLEPacketCodec(BinaryPacketCodec):

    def new_decode_buffer(self, data):
        ret = BinaryBuffer(data)
        ret.order('<')
        return ret

    def new_encode_buffer(self):
        ret = BinaryBuffer()
        ret.order('<')
        return ret

# Codec-specific annotations below


class SequenceTerminated(Annotation):

    def __init__(self, value, cond=''):
        self.tok = value
        self.cond = cond


class NullTerminated(SequenceTerminated):

    def __init__(self, value=1, cond=''):
        SequenceTerminated.__init__(self, '\x00' * value, cond)


class ReverseByteOrder(Annotation):

    def __init__(self):
        pass
