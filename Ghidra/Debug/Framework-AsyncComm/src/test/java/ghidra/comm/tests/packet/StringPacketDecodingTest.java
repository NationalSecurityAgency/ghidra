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

import org.junit.Before;
import org.junit.Test;

import ghidra.comm.packet.PacketCodec;
import ghidra.comm.packet.err.*;
import ghidra.comm.packet.string.StringPacketCodec;
import ghidra.comm.tests.packet.PacketTestClasses.*;
import ghidra.comm.tests.packet.PacketTestClasses.TestMessageEnum.TestEnum;

public class StringPacketDecodingTest {
	protected PacketCodec<String> codec; // Use the interface to ensure methods are defined there

	@Before
	public void setUp() {
		codec = StringPacketCodec.getInstance();
	}

	@Test
	public void testFlat() throws PacketDecodeException {
		codec.registerPacketType(TestMessageFlatTypes.class);
		codec.registerPacketType(TestMessageFlatMixedEndian.class);
		String enc;

		enc = "1,2,3,4,50,3c,seven,8.0,0x1.2p3";
		TestMessageFlatTypes p1 = codec.decodePacket(TestMessageFlatTypes.class, enc);
		TestMessageFlatTypes e1 =
			new TestMessageFlatTypes(true, (byte) 2, '3', (short) 4, 50, 60, "seven", 8, 9);
		assertEquals(e1, p1);

		enc = "1,2,3,4,five,six   7,8,9.0,10.0,11.0,12.0";
		TestMessageFlatMixedEndian p2 = codec.decodePacket(TestMessageFlatMixedEndian.class, enc);
		TestMessageFlatMixedEndian e2 =
			new TestMessageFlatMixedEndian('1', '2', 3, 4, "five", "six", 7, 8, 9, 10, 11, 12);
		assertEquals(e2, p2);
	}

	@Test
	public void testSizedAnnot() throws PacketDecodeException {
		codec.registerPacketType(TestMessageSizedString.class);
		codec.registerPacketType(TestMessageMethodSizedString.class);
		String enc;

		enc = "7,Testing4";
		TestMessageSizedString p1 = codec.decodePacket(TestMessageSizedString.class, enc);
		TestMessageSizedString e1 = new TestMessageSizedString("Testing", 4);
		e1.len = 7; // Have to set this manually for testing, since it's never encoded
		assertEquals(e1, p1);

		enc = "c,Testing2";
		TestMessageMethodSizedString p2 =
			codec.decodePacket(TestMessageMethodSizedString.class, enc);
		TestMessageMethodSizedString e2 = new TestMessageMethodSizedString("Testing2");
		e2.len = 12;
		assertEquals(e2, p2);
	}

	@Test
	public void testCountedAnnot() throws PacketDecodeException {
		codec.registerPacketType(TestMessageCountedShortArray.class);
		String enc;

		enc = "4,0,1,2,3;beef";
		TestMessageCountedShortArray p1 =
			codec.decodePacket(TestMessageCountedShortArray.class, enc);
		TestMessageCountedShortArray e1 =
			new TestMessageCountedShortArray(0xbeef, (short) 0, (short) 1, (short) 2, (short) 3);
		e1.count = 4;
		assertEquals(e1, p1);
	}

	@Test
	public void testTypedAnnot() throws PacketDecodeException {
		codec.registerPacketType(TestMessageDynamicTyped.class);
		codec.registerPacketType(TestMessageDynamicTypedSubs.class);
		String enc;

		enc = "1,3";
		TestMessageDynamicTyped p1 = codec.decodePacket(TestMessageDynamicTyped.class, enc);
		TestMessageDynamicTyped e1 = new TestMessageDynamicTyped(3);
		e1.type = 1;
		assertEquals(e1, p1);

		TestMessageDynamicTypedSubs p2 = codec.decodePacket(TestMessageDynamicTypedSubs.class, enc);
		TestMessageDynamicTypedSubs e2 =
			new TestMessageDynamicTypedSubs(new TestMessageDynamicTypedSubs.IntTestMessage(3));
		e2.type = 1;
		assertEquals(e2, p2);

		enc = "2,4";
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
	public void testCollection() throws PacketDecodeException, PacketEncodeException {
		codec.registerPacketType(TestMessageUnmeasuredCollection.class);
		codec.registerPacketType(TestMessageFullSpecColField.class);
		String enc;

		enc = "2,7,Testing" + "1,1,1" + "1,1,2";
		TestMessageUnmeasuredCollection p1 =
			codec.decodePacket(TestMessageUnmeasuredCollection.class, enc);
		TestMessageUnmeasuredCollection e1 = new TestMessageUnmeasuredCollection("Testing", 1, 2);
		codec.encodePacket(e1); // codec will initialize referenced fields (type, len)
		assertEquals(e1, p1);

		enc = "0,1,2,3";
		TestMessageFullSpecColField p2 = codec.decodePacket(TestMessageFullSpecColField.class, enc);
		TestMessageFullSpecColField e2 = new TestMessageFullSpecColField(0, 1, 2, 3);
		assertEquals(e2, p2);
	}

	@Test
	public void testLookahead() throws PacketDecodeException {
		codec.registerPacketType(TestMessageLookahead.class);
		String enc;

		enc = "Int3";
		TestMessageLookahead p1 = codec.decodePacket(TestMessageLookahead.class, enc);
		TestMessageLookahead e1 = new TestMessageLookahead(3);
		assertEquals(e1, p1);

		enc = "Long4";
		p1 = codec.decodePacket(TestMessageLookahead.class, enc);
		e1 = new TestMessageLookahead(4L);
		assertEquals(e1, p1);
	}

	@Test
	public void testDoubleTermed() throws PacketDecodeException {
		codec.registerPacketType(TestMessageDoubleTermed.class);
		String enc;

		enc = "7,Testing,";
		TestMessageDoubleTermed p1 = codec.decodePacket(TestMessageDoubleTermed.class, enc);
		TestMessageDoubleTermed e1 = new TestMessageDoubleTermed("Testing");
		e1.len = 7;
		assertEquals(e1, p1);
	}

	@Test
	public void testFixedSize() throws PacketDecodeException {
		codec.registerPacketType(TestMessageFixedSize.class);
		String enc;

		enc = "00000000000000010000000200000003";
		TestMessageFixedSize p1 = codec.decodePacket(TestMessageFixedSize.class, enc);
		TestMessageFixedSize e1 = new TestMessageFixedSize(0, 1, 2, 3);
		assertEquals(e1, p1);
	}

	@Test
	public void testOptional() throws PacketDecodeException {
		codec.registerPacketType(TestMessageOptional.class);
		String enc;

		enc = "SomeString";
		TestMessageOptional p1 = codec.decodePacket(TestMessageOptional.class, enc);
		TestMessageOptional e1 = new TestMessageOptional("SomeString");
		assertEquals(e1, p1);

		enc = "SomeString;33";
		p1 = codec.decodePacket(TestMessageOptional.class, enc);
		e1 = new TestMessageOptional("SomeString", 51);
		assertEquals(e1, p1);
	}

	@Test
	public void testEnum() throws PacketDecodeException {
		codec.registerPacketType(TestMessageEnum.class);
		String enc;

		enc = "ON33";
		TestMessageEnum p1 = codec.decodePacket(TestMessageEnum.class, enc);
		TestMessageEnum e1 = new TestMessageEnum(TestEnum.ON, 51);
		assertEquals(e1, p1);

		enc = "ONE33";
		p1 = codec.decodePacket(TestMessageEnum.class, enc);
		e1 = new TestMessageEnum(TestEnum.ONE, 51);
		assertEquals(e1, p1);

		enc = "NONE33";
		try {
			p1 = codec.decodePacket(TestMessageEnum.class, enc);
			fail();
		}
		catch (PacketFieldValueMismatchException e) {
			// pass
		}
	}

	@Test
	public void testHexString() throws PacketDecodeException {
		codec.registerPacketType(TestMessageHexString.class);
		String enc;

		enc = "54657374696e67";
		TestMessageHexString p1 = codec.decodePacket(TestMessageHexString.class, enc);
		TestMessageHexString e1 = new TestMessageHexString("Testing");
		assertEquals(e1, p1);
	}

	// TODO: Test Optional/Repeated vs. Repeated/Optional
}
