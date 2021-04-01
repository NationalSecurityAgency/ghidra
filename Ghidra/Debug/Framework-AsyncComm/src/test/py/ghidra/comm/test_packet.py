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
from test import test_support
import unittest

from .packet import Packet, DefaultPacketFactory, DEFAULT_FACTORY
from .packet.binary import BinaryPacketCodec
from .tests.packet import *
from .util import BitmaskSet


def update_list(left, right):
    for i, (l, r) in enumerate(zip(left, right)):
        if isinstance(l, Packet) and isinstance(r, dict):
            update_packet(l, r)
        elif isinstance(l, list) and isinstance(r, list):
            assert len(l) == len(r)
            update_list(l, r)
        else:
            left[i] = r


def update_packet(pkt, vals):
    for k, v in vals.items():
        cur = getattr(pkt, k)
        if isinstance(cur, Packet) and isinstance(v, dict):
            update_packet(cur, v)
        elif isinstance(cur, list) and isinstance(v, list):
            assert len(k) == len(v)
            update_list(cur, v)
        else:
            setattr(pkt, k, v)


class BinaryPacketCodecTest(unittest.TestCase):

    factory = DEFAULT_FACTORY

    def build_dec(self):
        if isinstance(self.dec_parts, tuple):
            return self.pkt_cls(*self.dec_parts)
        else:
            return self.pkt_cls(**self.dec_parts)

    def setUp(self):
        self.codec = BinaryPacketCodec()
        self.codec.register_packet_cls(self.pkt_cls)
        self.factory.register_types(self.codec)
        self.enc = bytes(''.join(self.enc_parts))
        self.pkt = self.build_dec()
        if hasattr(self, 'dec_extra'):
            self.dec = self.build_dec()
            update_packet(self.dec, self.dec_extra)
        else:
            self.dec = self.pkt

    def test_encode(self):
        enc = self.codec.encode_packet(self.pkt)
        self.assertEquals(self.enc, enc)

    def test_decode(self):
        dec = self.codec.decode_packet(self.pkt_cls, self.enc, self.factory)
        self.assertEquals(self.dec, dec)


class TestFlatTypes(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageFlatTypes
    enc_parts = ('\x01', '\x02', '\x00\x33', '\x00\x04', '\x00\x00\x00\x05',
                 '\x00\x00\x00\x00\x00\x00\x00\x06', 'seven\x00',
                 '\x41\x00\x00\x00', '\x40\x22\x00\x00\x00\x00\x00\x00')
    dec_parts = (True, 2, '3', 4, 5, 6, 'seven', 8, 9)


class TestFlatMixedEndian(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageFlatMixedEndian
    enc_parts = ('\x00\x31', '\x32\x00', '\x00\x00\x00\x03',
                 '\x04\x00\x00\x00', 'five\x00', 'six\x00\x00',
                 '\x00\x00\x00\x00\x00\x00\x00\x07',
                 '\x08\x00\x00\x00\x00\x00\x00\x00',
                 '\x41\x10\x00\x00', '\x00\x00\x20\x41',
                 '\x40\x26\x00\x00\x00\x00\x00\x00',
                 '\x00\x00\x00\x00\x00\x00\x28\x40')
    dec_parts = ('1', '2', 3, 4, 'five', 'six', 7, 8, 9, 10, 11, 12)


class TestSizedString(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageSizedString
    enc_parts = ('\x00\x00\x00\x07', 'Testing', '\x00\x00\x00\x04')
    dec_parts = dict(str='Testing', more=4)
    dec_extra = dict(len=7)


class TestMethodSizedString(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageMethodSizedString
    enc_parts = ('\x00\x00\x00\x0c', 'Testing2')
    dec_parts = dict(str='Testing2')
    dec_extra = dict(len=12)

    def setUp(self):
        BinaryPacketCodecTest.setUp(self)

        def getLen(self):
            return self.len - 4

        def setLen(self, len):
            self.len = len + 4

        PacketTestClasses_TestMessageMethodSizedString.getLen = getLen
        PacketTestClasses_TestMessageMethodSizedString.setLen = setLen


class TestCountedShortArray(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageCountedShortArray
    enc_parts = ('\x00\x00\x00\x04', '\x00\x00', '\x01\x00',
                 '\x02\x00', '\x03\x00', '\x00\x00\xbe\xef')
    dec_parts = dict(more=0xbeef, arr=[0, 1, 2, 3])
    dec_extra = dict(count=4)


class TestDynamicTyped1(BinaryPacketCodecTest):
    # NOTE: Not sure how to test/implement the plain TestMessageDynamicTyped
    # The type of the field takes Integer or Long, which are indistinguishable
    # in Python
    pkt_cls = PacketTestClasses_TestMessageDynamicTypedSubs
    enc_parts = ('\x00\x00\x00\x01', '\x00\x00\x00\x03')
    dec_parts = dict(
        sub=PacketTestClasses_TestMessageDynamicTypedSubs_IntTestMessage(3))
    dec_extra = dict(type=1)


class TestDynamicTyped2(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageDynamicTypedSubs
    enc_parts = ('\x00\x00\x00\x02', '\x00\x00\x00\x00\x00\x00\x00\x04')
    dec_parts = dict(
        sub=PacketTestClasses_TestMessageDynamicTypedSubs_LongTestMessage(4))
    dec_extra = dict(type=2)


class TestUnmeasuredCollection(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageUnmeasuredCollection
    enc_parts = ('\x02', '\x00\x07', 'Testing',
                 '\x01', '\x00\x04', '\x00\x00\x00\x01',
                 '\x01', '\x00\x04', '\x00\x00\x00\x02')
    dec_parts = ([
        PacketTestClasses_TestMessageUnmeasuredCollection_TestElement(
            val='Testing'),
        PacketTestClasses_TestMessageUnmeasuredCollection_TestElement(val=1),
        PacketTestClasses_TestMessageUnmeasuredCollection_TestElement(val=2),
    ],)
    dec_extra = dict(col=[
        dict(type=2, len=7),
        dict(type=1, len=4),
        dict(type=1, len=4),
    ])


class TestFullSpecColField(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageFullSpecColField
    enc_parts = ('\x00\x00\x00\x00', '\x00\x00\x00\x01',
                 '\x00\x00\x00\x02', '\x00\x00\x00\x03')
    dec_parts = ([0, 1, 2, 3],)


class TestLookahead1(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageLookahead
    enc_parts = ('Int', '\x00\x00\x00\x03')
    dec_parts = (PacketTestClasses_TestMessageLookahead_IntTestMessage(3),)


class TestLookahead2(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageLookahead
    enc_parts = ('Long', '\x00\x00\x00\x00\x00\x00\x00\x04')
    dec_parts = (PacketTestClasses_TestMessageLookahead_LongTestMessage(4),)


class TestDoubleTermed(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageDoubleTermed
    enc_parts = ('\x00\x00\x00\x07', 'Testing\x00')
    dec_parts = dict(str='Testing')
    dec_extra = dict(len=7)


class TestOptional1(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageOptional
    enc_parts = ('SomeString',)
    dec_parts = dict(f1='SomeString')


class TestOptional2(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageOptional
    enc_parts = ('SomeString\x00', '\x00\x00\x00\x33')
    dec_parts = dict(f1='SomeString', opt=51)


class TestEnum1(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageEnum
    enc_parts = ('\x01', '\x00\x00\x00\x33')
    dec_parts = (PacketTestClasses_TestMessageEnum_TestEnum.ON, 51)


class TestEnum2(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageEnum
    enc_parts = ('\x02', '\x00\x00\x00\x33')
    dec_parts = (PacketTestClasses_TestMessageEnum_TestEnum.ONE, 51)


class LongFactory(DefaultPacketFactory):

    def register_types(self, codec):
        codec.register_packet_cls(PacketTestClasses_LongTestNumber)

    def new_packet(self, pktCls):
        #print("new_packet: %r" % (pktCls))
        if pktCls == PacketTestClasses_AbstractTestNumber:
            #print("  Provided LongTestNumber")
            return PacketTestClasses_LongTestNumber()
        #print("  Provided default")
        return DefaultPacketFactory.new_packet(self, pktCls)


class TestAbstract1(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageAbstractTestNumber
    enc_parts = (
        '\x00\x00\x00\x02',
        '\x00\x00\x00\x00\x00\x00\x00\x05',
        '\x00\x00\x00\x00\x00\x00\x00\x06',
        '\x00\x00\x30\x39',
    )
    dec_parts = dict(
        numbers=[
            PacketTestClasses_LongTestNumber(5),
            PacketTestClasses_LongTestNumber(6),
        ],
        follows=12345,
    )

    factory = LongFactory()
    dec_extra = dict(count=2)


class IntFactory(DefaultPacketFactory):

    def register_types(self, codec):
        codec.register_packet_cls(PacketTestClasses_IntTestNumber)

    def new_packet(self, pktCls):
        if pktCls == PacketTestClasses_AbstractTestNumber:
            return PacketTestClasses_IntTestNumber()
        return DefaultPacketFactory.new_packet(self, pktCls)


class TestAbstract2(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageAbstractTestNumber
    enc_parts = (
        '\x00\x00\x00\x02',
        '\x00\x00\x00\x05',
        '\x00\x00\x00\x06',
        '\x00\x00\x30\x39',
    )
    dec_parts = dict(
        numbers=[
            PacketTestClasses_IntTestNumber(5),
            PacketTestClasses_IntTestNumber(6),
        ],
        follows=12345,
    )

    factory = IntFactory()
    dec_extra = dict(count=2)


class TestTypedByMap1(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageTypedByMap
    enc_parts = ('\x00', '\x00\x00\x00\x05')
    dec_parts = dict(
        sub=PacketTestClasses_TestMessageTypedByMap_TestASubByMap(5))
    dec_extra = dict(type=PacketTestClasses_TestMessageTypedByMap_TestEnum.A)


class TestTypedByMap2(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageTypedByMap
    enc_parts = ('\x01', '\x00\x00\x00\x00\x00\x00\x00\x06')
    dec_parts = dict(
        sub=PacketTestClasses_TestMessageTypedByMap_TestBSubByMap(6))
    dec_extra = dict(type=PacketTestClasses_TestMessageTypedByMap_TestEnum.B)


class TestFlags1(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageFlags
    enc_parts = ('\x02')
    dec_parts = dict()
    dec_extra = dict(flags=BitmaskSet.of(
        PacketTestClasses_TestMessageFlags_TestFlags,
        PacketTestClasses_TestMessageFlags_TestFlags.SECOND
    ))


class TestFlags2(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageFlags
    enc_parts = ('\x03', '\x11\x22\x33\x44\x55\x66\x77\x88')
    dec_parts = dict(first=0x1122334455667788L)
    dec_extra = dict(flags=BitmaskSet.of(
        PacketTestClasses_TestMessageFlags_TestFlags,
        PacketTestClasses_TestMessageFlags_TestFlags.FIRST,
        PacketTestClasses_TestMessageFlags_TestFlags.SECOND,
    ))


class TestFlags3(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageFlags
    enc_parts = ('\x00', '\x12\x34\x56\x78')
    dec_parts = dict(second=0x12345678)
    dec_extra = dict(flags=BitmaskSet.of(
        PacketTestClasses_TestMessageFlags_TestFlags,
    ))


class TestFlags4(BinaryPacketCodecTest):
    pkt_cls = PacketTestClasses_TestMessageFlags
    enc_parts = ('\x01', '\x11\x22\x33\x44\x55\x66\x77\x88',
                 '\x12\x34\x56\x78')
    dec_parts = dict(first=0x1122334455667788L, second=0x12345678)
    dec_extra = dict(flags=BitmaskSet.of(
        PacketTestClasses_TestMessageFlags_TestFlags,
        PacketTestClasses_TestMessageFlags_TestFlags.FIRST,
    ))


def test_main():
    test_support.run_unittest(
        TestFlatTypes,
        TestFlatMixedEndian,
        TestSizedString,
        TestMethodSizedString,
        TestCountedShortArray,
        TestDynamicTyped1,
        TestDynamicTyped2,
        TestUnmeasuredCollection,
        TestFullSpecColField,
        TestLookahead1,
        TestLookahead2,
        TestDoubleTermed,
        TestOptional1,
        TestOptional2,
        TestEnum1,
        TestEnum2,
        TestAbstract1,
        TestAbstract2,
        TestTypedByMap1,
        TestTypedByMap2,
        TestFlags1,
        TestFlags2,
        TestFlags3,
        TestFlags4,
    )


if __name__ == '__main__':
    test_main()
