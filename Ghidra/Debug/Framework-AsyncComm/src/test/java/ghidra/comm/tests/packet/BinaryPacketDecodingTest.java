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
import static org.junit.Assert.fail;

import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Test;

import ghidra.comm.packet.PacketCodec;
import ghidra.comm.packet.binary.BinaryPacketCodec;
import ghidra.comm.packet.err.*;
import ghidra.comm.tests.packet.PacketTestClasses.TestMessageEnum.TestEnum;
import ghidra.comm.tests.packet.PacketTestClasses.TestMessageFlags.TestFlags;
import ghidra.comm.tests.packet.PacketTestClasses.TestMessageTypedByMap.TestASubByMap;
import ghidra.comm.tests.packet.PacketTestClasses.TestMessageTypedByMap.TestBSubByMap;
import ghidra.comm.util.BitmaskSet;
import ghidra.util.NumericUtilities;

public class BinaryPacketDecodingTest implements PacketTestClasses {
	protected PacketCodec<byte[]> codec; // Use the interface to ensure methods are defined there

	@Before
	public void setUp() {
		codec = BinaryPacketCodec.getInstance();
	}

	public static byte[] consPacket(String... parts) {
		String full = StringUtils.join(parts).replace(":", "");
		return NumericUtilities.convertStringToBytes(full);
	}

	@Test
	public void testFlat() throws PacketDecodeException, FieldOrderingException {
		codec.registerPacketType(TestMessageFlatTypes.class);
		codec.registerPacketType(TestMessageFlatMixedEndian.class);
		byte[] enc;

		enc = consPacket("01", "02", "00:33", "00:04", "00:00:00:05", "00:00:00:00:00:00:00:06",
			"73:65:76:65:6e:00", "41:00:00:00", "40:22:00:00:00:00:00:00");
		TestMessageFlatTypes p1 = codec.decodePacket(TestMessageFlatTypes.class, enc);
		assertEquals(new TestMessageFlatTypes(true, (byte) 2, '3', (short) 4, 5, 6, "seven", 8, 9),
			p1);

		enc = consPacket("00:31", "32:00", "00:00:00:03", "04:00:00:00", "66:69:76:65:00",
			"73:69:78:00:00", "00:00:00:00:00:00:00:07", "08:00:00:00:00:00:00:00", "41:10:00:00",
			"00:00:20:41", "40:26:00:00:00:00:00:00", "00:00:00:00:00:00:28:40");
		TestMessageFlatMixedEndian p2 = codec.decodePacket(TestMessageFlatMixedEndian.class, enc);
		assertEquals(
			new TestMessageFlatMixedEndian('1', '2', 3, 4, "five", "six", 7, 8, 9, 10, 11, 12), p2);
	}

	@Test
	public void testSizedAnnot() throws PacketDecodeException, FieldOrderingException {
		codec.registerPacketType(TestMessageSizedString.class);
		codec.registerPacketType(TestMessageMethodSizedString.class);
		byte[] enc;

		enc = consPacket("00:00:00:07", "54:65:73:74:69:6e:67", "00:00:00:04");
		TestMessageSizedString p1 = codec.decodePacket(TestMessageSizedString.class, enc);
		TestMessageSizedString e1 = new TestMessageSizedString("Testing", 4);
		e1.len = 7; // Have to set this manually for testing, since it's never encoded
		assertEquals(e1, p1);

		enc = consPacket("00:00:00:0c", "54:65:73:74:69:6e:67:32");
		TestMessageMethodSizedString p2 =
			codec.decodePacket(TestMessageMethodSizedString.class, enc);
		TestMessageMethodSizedString e2 = new TestMessageMethodSizedString("Testing2");
		e2.len = 12;
		assertEquals(e2, p2);
	}

	@Test
	public void testCountedAnnot() throws PacketDecodeException, FieldOrderingException {
		codec.registerPacketType(TestMessageCountedShortArray.class);
		byte[] enc;

		enc = consPacket("00:00:00:04", "00:00", "01:00", "02:00", "03:00", "00:00:be:ef");
		TestMessageCountedShortArray p1 =
			codec.decodePacket(TestMessageCountedShortArray.class, enc);
		TestMessageCountedShortArray e1 =
			new TestMessageCountedShortArray(0xbeef, (short) 0, (short) 1, (short) 2, (short) 3);
		e1.count = 4;
		assertEquals(e1, p1);
	}

	@Test
	public void testTypedAnnot() throws PacketDecodeException, FieldOrderingException {
		codec.registerPacketType(TestMessageDynamicTyped.class);
		codec.registerPacketType(TestMessageDynamicTypedSubs.class);
		byte[] enc;

		enc = consPacket("00:00:00:01", "00:00:00:03");
		TestMessageDynamicTyped p1 = codec.decodePacket(TestMessageDynamicTyped.class, enc);
		TestMessageDynamicTyped e1 = new TestMessageDynamicTyped(3);
		e1.type = 1;
		assertEquals(e1, p1);

		TestMessageDynamicTypedSubs p2 = codec.decodePacket(TestMessageDynamicTypedSubs.class, enc);
		TestMessageDynamicTypedSubs e2 =
			new TestMessageDynamicTypedSubs(new TestMessageDynamicTypedSubs.IntTestMessage(3));
		e2.type = 1;
		assertEquals(e2, p2);

		enc = consPacket("00:00:00:02", "00:00:00:00:00:00:00:04");
		p1 = codec.decodePacket(TestMessageDynamicTyped.class, enc);
		e1 = new TestMessageDynamicTyped(4L);
		e1.type = 2;
		assertEquals(e1, p1);

		p2 = codec.decodePacket(TestMessageDynamicTypedSubs.class, enc);
		e2 = new TestMessageDynamicTypedSubs(new TestMessageDynamicTypedSubs.LongTestMessage(4));
		e2.type = 2;
		assertEquals(e2, p2);
	}

	@Test
	public void testCollection()
			throws PacketDecodeException, PacketEncodeException, FieldOrderingException {
		codec.registerPacketType(TestMessageUnmeasuredCollection.class);
		codec.registerPacketType(TestMessageFullSpecColField.class);
		byte[] enc;

		enc = consPacket(//
			"02", "00:07", "54:65:73:74:69:6e:67", //
			"01", "00:04", "00:00:00:01", //
			"01", "00:04", "00:00:00:02");
		TestMessageUnmeasuredCollection p1 =
			codec.decodePacket(TestMessageUnmeasuredCollection.class, enc);
		TestMessageUnmeasuredCollection e1 = new TestMessageUnmeasuredCollection("Testing", 1, 2);
		codec.encodePacket(e1); // codec will initialize referenced fields (type, len)
		assertEquals(e1, p1);

		enc = consPacket("00:00:00:00", "00:00:00:01", "00:00:00:02", "00:00:00:03");
		TestMessageFullSpecColField p2 = codec.decodePacket(TestMessageFullSpecColField.class, enc);
		TestMessageFullSpecColField e2 = new TestMessageFullSpecColField(0, 1, 2, 3);
		assertEquals(e2, p2);
	}

	@Test
	public void testLookahead() throws PacketDecodeException, FieldOrderingException {
		codec.registerPacketType(TestMessageLookahead.class);
		byte[] enc;

		enc = consPacket("49:6e:74", "00:00:00:03");
		TestMessageLookahead p1 = codec.decodePacket(TestMessageLookahead.class, enc);
		TestMessageLookahead e1 = new TestMessageLookahead(3);
		assertEquals(e1, p1);

		enc = consPacket("4c:6f:6e:67", "00:00:00:00:00:00:00:04");
		p1 = codec.decodePacket(TestMessageLookahead.class, enc);
		e1 = new TestMessageLookahead(4L);
		assertEquals(e1, p1);
	}

	@Test
	public void testDoubleTermed() throws PacketDecodeException, FieldOrderingException {
		codec.registerPacketType(TestMessageDoubleTermed.class);
		byte[] enc;

		enc = consPacket("00:00:00:07", "54:65:73:74:69:6e:67", "00");
		TestMessageDoubleTermed p1 = codec.decodePacket(TestMessageDoubleTermed.class, enc);
		TestMessageDoubleTermed e1 = new TestMessageDoubleTermed("Testing");
		e1.len = 7;
		assertEquals(e1, p1);
	}

	@Test
	public void testOptional() throws PacketDecodeException {
		codec.registerPacketType(TestMessageOptional.class);
		byte[] enc;

		enc = consPacket("53:6f:6d:65:53:74:72:69:6e:67");
		TestMessageOptional p1 = codec.decodePacket(TestMessageOptional.class, enc);
		TestMessageOptional e1 = new TestMessageOptional("SomeString");
		assertEquals(e1, p1);

		enc = consPacket("53:6f:6d:65:53:74:72:69:6e:67", "00", "00:00:00:33");
		p1 = codec.decodePacket(TestMessageOptional.class, enc);
		e1 = new TestMessageOptional("SomeString", 51);
		assertEquals(e1, p1);
	}

	@Test
	public void testEnum() throws PacketDecodeException {
		codec.registerPacketType(TestMessageEnum.class);
		byte[] enc;

		enc = consPacket("01", "00:00:00:33");
		TestMessageEnum p1 = codec.decodePacket(TestMessageEnum.class, enc);
		TestMessageEnum e1 = new TestMessageEnum(TestEnum.ON, 51);
		assertEquals(e1, p1);

		enc = consPacket("02", "00:00:00:33");
		p1 = codec.decodePacket(TestMessageEnum.class, enc);
		e1 = new TestMessageEnum(TestEnum.ONE, 51);
		assertEquals(e1, p1);

		enc = consPacket("05", "00:00:00:33");
		try {
			p1 = codec.decodePacket(TestMessageEnum.class, enc);
			fail();
		}
		catch (PacketFieldValueMismatchException e) {
			// pass
		}
	}

	@Test
	public void testNoEmpty() {
		codec.registerPacketType(TestMessageEmpty.class);
		byte[] enc;

		enc = consPacket("00");
		try {
			@SuppressWarnings("unused")
			TestMessageEmpty p1 = codec.decodePacket(TestMessageEmpty.class, enc);
			fail();
		}
		catch (PacketDecodeException e) {
			// pass
		}
	}

	@Test
	public void testAbstract() throws PacketDecodeException {
		codec.registerPacketType(TestMessageAbstractTestNumber.class);
		PacketTestClasses.LONG_TEST_NUMBER_FACTORY.registerTypes(codec);
		PacketTestClasses.INT_TEST_NUMBER_FACTORY.registerTypes(codec);
		byte[] enc;

		enc = consPacket("00:00:00:02", "00:00:00:00:00:00:00:05", "00:00:00:00:00:00:00:06",
			"00:00:30:39");
		TestMessageAbstractTestNumber p1 = codec.decodePacket(TestMessageAbstractTestNumber.class,
			enc, PacketTestClasses.LONG_TEST_NUMBER_FACTORY);
		TestMessageAbstractTestNumber e1 =
			new TestMessageAbstractTestNumber(12345, new LongTestNumber(5), new LongTestNumber(6));
		e1.count = 2;
		assertEquals(e1, p1);

		enc = consPacket("00:00:00:02", "00:00:00:05", "00:00:00:06", "00:00:30:39");
		p1 = codec.decodePacket(TestMessageAbstractTestNumber.class, enc,
			PacketTestClasses.INT_TEST_NUMBER_FACTORY);
		e1 = new TestMessageAbstractTestNumber(12345, new IntTestNumber(5), new IntTestNumber(6));
		e1.count = 2;
		assertEquals(e1, p1);
	}

	@Test
	public void testTypedByMap() throws PacketDecodeException {
		codec.registerPacketType(TestMessageTypedByMap.class);
		byte[] enc;

		enc = consPacket("00", "00:00:00:05");
		TestMessageTypedByMap p1 = codec.decodePacket(TestMessageTypedByMap.class, enc);
		TestMessageTypedByMap e1 = new TestMessageTypedByMap(new TestASubByMap(5));
		e1.type = TestMessageTypedByMap.TestEnum.A;
		assertEquals(e1, p1);

		enc = consPacket("01", "00:00:00:00:00:00:00:06");
		p1 = codec.decodePacket(TestMessageTypedByMap.class, enc);
		e1 = new TestMessageTypedByMap(new TestBSubByMap(6));
		e1.type = TestMessageTypedByMap.TestEnum.B;
		assertEquals(e1, p1);
	}

	@Test
	public void testFlags() throws PacketDecodeException {
		codec.registerPacketType(TestMessageFlags.class);
		byte[] enc;

		enc = consPacket("02");
		TestMessageFlags p1 = codec.decodePacket(TestMessageFlags.class, enc);
		TestMessageFlags e1 = new TestMessageFlags();
		e1.flags = BitmaskSet.of(TestFlags.SECOND);
		assertEquals(e1, p1);

		enc = consPacket("03", "11:22:33:44:55:66:77:88");
		p1 = codec.decodePacket(TestMessageFlags.class, enc);
		e1 = new TestMessageFlags(0x1122334455667788L);
		e1.flags = BitmaskSet.of(TestFlags.FIRST, TestFlags.SECOND);
		assertEquals(e1, p1);

		enc = consPacket("00", "12:34:56:78");
		p1 = codec.decodePacket(TestMessageFlags.class, enc);
		e1 = new TestMessageFlags(0x12345678);
		e1.flags = BitmaskSet.of();
		assertEquals(e1, p1);

		enc = consPacket("01", "11:22:33:44:55:66:77:88", "12:34:56:78");
		p1 = codec.decodePacket(TestMessageFlags.class, enc);
		e1 = new TestMessageFlags(0x1122334455667788L, 0x12345678);
		e1.flags = BitmaskSet.of(TestFlags.FIRST);
		assertEquals(e1, p1);
	}
}
