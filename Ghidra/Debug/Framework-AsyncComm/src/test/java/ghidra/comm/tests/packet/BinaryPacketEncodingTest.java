/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.comm.tests.packet;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import ghidra.comm.packet.PacketCodec;
import ghidra.comm.packet.binary.BinaryPacketCodec;
import ghidra.comm.packet.err.FieldOrderingException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.tests.packet.PacketTestClasses.TestMessageEnum.TestEnum;
import ghidra.comm.tests.packet.PacketTestClasses.TestMessageTypedByMap.TestASubByMap;
import ghidra.comm.tests.packet.PacketTestClasses.TestMessageTypedByMap.TestBSubByMap;
import ghidra.util.NumericUtilities;

public class BinaryPacketEncodingTest implements PacketTestClasses {
	protected PacketCodec<byte[]> codec;

	@Before
	public void setUp() {
		codec = BinaryPacketCodec.getInstance();
	}

	@Test
	public void testFlat() throws PacketEncodeException, FieldOrderingException {
		codec.registerPacketType(TestMessageFlatTypes.class);
		codec.registerPacketType(TestMessageFlatMixedEndian.class);
		byte[] enc;

		enc = codec.encodePacket(
			new TestMessageFlatTypes(true, (byte) 2, '3', (short) 4, 5, 6, "seven", 8, 9));
		assertEquals(
			"01:" + "02:" + "00:33:" + "00:04:" + "00:00:00:05:" + "00:00:00:00:00:00:00:06:" +
				"73:65:76:65:6e:00:" + "41:00:00:00:" + "40:22:00:00:00:00:00:00",
			NumericUtilities.convertBytesToString(enc, ":"));

		enc = codec.encodePacket(
			new TestMessageFlatMixedEndian('1', '2', 3, 4, "five", "six", 7, 8, 9, 10, 11, 12));
		assertEquals("00:31:" + "32:00:" + "00:00:00:03:" + "04:00:00:00:" + "66:69:76:65:00:" +
			"73:69:78:00:00:" + "00:00:00:00:00:00:00:07:" + "08:00:00:00:00:00:00:00:" +
			"41:10:00:00:" + "00:00:20:41:" + "40:26:00:00:00:00:00:00:" +
			"00:00:00:00:00:00:28:40", NumericUtilities.convertBytesToString(enc, ":"));
	}

	@Test
	public void testSizedAnnot() throws PacketEncodeException, FieldOrderingException {
		codec.registerPacketType(TestMessageSizedString.class);
		codec.registerPacketType(TestMessageMethodSizedString.class);
		byte[] enc;

		enc = codec.encodePacket(new TestMessageSizedString("Testing", 4));
		assertEquals("00:00:00:07:" + "54:65:73:74:69:6e:67:" + "00:00:00:04",
			NumericUtilities.convertBytesToString(enc, ":"));

		enc = codec.encodePacket(new TestMessageMethodSizedString("Testing2"));
		assertEquals("00:00:00:0c:" + "54:65:73:74:69:6e:67:32",
			NumericUtilities.convertBytesToString(enc, ":"));
	}

	@Test
	public void testCountedAnnot() throws PacketEncodeException, FieldOrderingException {
		codec.registerPacketType(TestMessageCountedShortArray.class);
		byte[] enc;

		enc = codec.encodePacket(
			new TestMessageCountedShortArray(0xbeef, (short) 0, (short) 1, (short) 2, (short) 3));
		assertEquals("00:00:00:04:" + "00:00:" + "01:00:" + "02:00:" + "03:00:" + "00:00:be:ef",
			NumericUtilities.convertBytesToString(enc, ":"));
	}

	@Test
	public void testTypedAnnot() throws PacketEncodeException, FieldOrderingException {
		codec.registerPacketType(TestMessageDynamicTyped.class);
		codec.registerPacketType(TestMessageDynamicTypedSubs.class);
		byte[] enc;

		enc = codec.encodePacket(new TestMessageDynamicTyped(3));
		assertEquals("00:00:00:01:" + "00:00:00:03",
			NumericUtilities.convertBytesToString(enc, ":"));

		enc = codec.encodePacket(new TestMessageDynamicTyped(4L));
		assertEquals("00:00:00:02:" + "00:00:00:00:00:00:00:04",
			NumericUtilities.convertBytesToString(enc, ":"));

		enc = codec.encodePacket(
			new TestMessageDynamicTypedSubs(new TestMessageDynamicTypedSubs.IntTestMessage(3)));
		assertEquals("00:00:00:01:" + "00:00:00:03",
			NumericUtilities.convertBytesToString(enc, ":"));

		enc = codec.encodePacket(
			new TestMessageDynamicTypedSubs(new TestMessageDynamicTypedSubs.LongTestMessage(4)));
		assertEquals("00:00:00:02:" + "00:00:00:00:00:00:00:04",
			NumericUtilities.convertBytesToString(enc, ":"));
	}

	@Test
	public void testCollection() throws PacketEncodeException, FieldOrderingException {
		codec.registerPacketType(TestMessageUnmeasuredCollection.class);
		codec.registerPacketType(TestMessageFullSpecColField.class);
		byte[] enc;

		enc = codec.encodePacket(new TestMessageUnmeasuredCollection("Testing", 1, 2));
		assertEquals("" +//
			"02:" + "00:07:" + "54:65:73:74:69:6e:67:" + //
			"01:" + "00:04:" + "00:00:00:01:" + //
			"01:" + "00:04:" + "00:00:00:02", //
			NumericUtilities.convertBytesToString(enc, ":"));

		enc = codec.encodePacket(new TestMessageFullSpecColField(0, 1, 2, 3));
		assertEquals("00:00:00:00:" + "00:00:00:01:" + "00:00:00:02:" + "00:00:00:03",
			NumericUtilities.convertBytesToString(enc, ":"));
	}

	@Test
	public void testLookahead() throws PacketEncodeException, FieldOrderingException {
		codec.registerPacketType(TestMessageLookahead.class);
		byte[] enc;

		enc = codec.encodePacket(new TestMessageLookahead(3));
		assertEquals("49:6e:74:" + "00:00:00:03", NumericUtilities.convertBytesToString(enc, ":"));

		enc = codec.encodePacket(new TestMessageLookahead(4L));
		assertEquals("4c:6f:6e:67:" + "00:00:00:00:00:00:00:04",
			NumericUtilities.convertBytesToString(enc, ":"));
	}

	@Test
	public void testDoubleTermed() throws PacketEncodeException, FieldOrderingException {
		codec.registerPacketType(TestMessageDoubleTermed.class);
		byte[] enc;

		enc = codec.encodePacket(new TestMessageDoubleTermed("Testing"));
		assertEquals("00:00:00:07:" + "54:65:73:74:69:6e:67:" + "00",
			NumericUtilities.convertBytesToString(enc, ":"));
	}

	@Test
	public void testOptional() throws PacketEncodeException {
		codec.registerPacketType(TestMessageOptional.class);
		byte[] enc;

		enc = codec.encodePacket(new TestMessageOptional("SomeString"));
		assertEquals("53:6f:6d:65:53:74:72:69:6e:67",
			NumericUtilities.convertBytesToString(enc, ":"));

		enc = codec.encodePacket(new TestMessageOptional("SomeString", 51));
		assertEquals("53:6f:6d:65:53:74:72:69:6e:67:" + "00:" + "00:00:00:33",
			NumericUtilities.convertBytesToString(enc, ":"));
	}

	@Test
	public void testEnum() throws PacketEncodeException {
		codec.registerPacketType(TestMessageEnum.class);
		byte[] enc;

		enc = codec.encodePacket(new TestMessageEnum(TestEnum.ON, 51));
		assertEquals("01:" + "00:00:00:33", NumericUtilities.convertBytesToString(enc, ":"));

		enc = codec.encodePacket(new TestMessageEnum(TestEnum.ONE, 51));
		assertEquals("02:" + "00:00:00:33", NumericUtilities.convertBytesToString(enc, ":"));
	}

	@Test
	public void testAbstract() throws PacketEncodeException {
		codec.registerPacketType(TestMessageAbstractTestNumber.class);
		PacketTestClasses.LONG_TEST_NUMBER_FACTORY.registerTypes(codec);
		PacketTestClasses.INT_TEST_NUMBER_FACTORY.registerTypes(codec);
		byte[] enc;

		enc = codec.encodePacket(
			new TestMessageAbstractTestNumber(12345, new LongTestNumber(5), new LongTestNumber(6)));
		assertEquals("00:00:00:02:" + "00:00:00:00:00:00:00:05:" + "00:00:00:00:00:00:00:06:" +
			"00:00:30:39", NumericUtilities.convertBytesToString(enc, ":"));

		enc = codec.encodePacket(
			new TestMessageAbstractTestNumber(12345, new IntTestNumber(5), new IntTestNumber(6)));
		assertEquals("00:00:00:02:" + "00:00:00:05:" + "00:00:00:06:" + "00:00:30:39",
			NumericUtilities.convertBytesToString(enc, ":"));
	}

	@Test
	public void testTypedByMap() throws PacketEncodeException {
		codec.registerPacketType(TestMessageTypedByMap.class);
		byte[] enc;

		enc = codec.encodePacket(new TestMessageTypedByMap(new TestASubByMap(5)));
		assertEquals("00:" + "00:00:00:05", NumericUtilities.convertBytesToString(enc, ":"));

		enc = codec.encodePacket(new TestMessageTypedByMap(new TestBSubByMap(6)));
		assertEquals("01:" + "00:00:00:00:00:00:00:06",
			NumericUtilities.convertBytesToString(enc, ":"));
	}

	@Test
	public void testFlags() throws PacketEncodeException {
		codec.registerPacketType(TestMessageFlags.class);
		byte[] enc;

		enc = codec.encodePacket(new TestMessageFlags());
		assertEquals("02", NumericUtilities.convertBytesToString(enc, ":"));

		enc = codec.encodePacket(new TestMessageFlags(0x1122334455667788L));
		assertEquals("03:" + "11:22:33:44:55:66:77:88",
			NumericUtilities.convertBytesToString(enc, ":"));

		enc = codec.encodePacket(new TestMessageFlags(0x12345678));
		assertEquals("00:" + "12:34:56:78", NumericUtilities.convertBytesToString(enc, ":"));

		enc = codec.encodePacket(new TestMessageFlags(0x1122334455667788L, 0x12345678));
		assertEquals("01:" + "11:22:33:44:55:66:77:88:" + "12:34:56:78",
			NumericUtilities.convertBytesToString(enc, ":"));
	}
}
