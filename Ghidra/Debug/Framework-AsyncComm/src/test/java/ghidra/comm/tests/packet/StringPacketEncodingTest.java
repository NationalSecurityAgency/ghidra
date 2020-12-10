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
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.string.StringPacketCodec;
import ghidra.comm.tests.packet.PacketTestClasses.TestMessageEnum.TestEnum;

public class StringPacketEncodingTest implements PacketTestClasses {
	protected PacketCodec<String> codec;

	@Before
	public void setUp() {
		codec = StringPacketCodec.getInstance();
	}

	@Test
	public void testFlat() throws PacketEncodeException {
		codec.registerPacketType(TestMessageFlatTypes.class);
		codec.registerPacketType(TestMessageFlatMixedEndian.class);
		String enc;

		enc = codec.encodePacket(
			new TestMessageFlatTypes(true, (byte) 2, '3', (short) 4, 50, 60, "seven", 8, 9));
		assertEquals("1,2,3,4,50,3c,seven,8.0,0x1.2p3", enc);

		enc = codec.encodePacket(
			new TestMessageFlatMixedEndian('1', '2', 3, 4, "five", "six", 7, 8, 9, 10, 11, 12));
		assertEquals("1,2,3,4,five,six 7,8,9.0,10.0,11.0,12.0", enc);
	}

	@Test
	public void testSizedAnnot() throws PacketEncodeException {
		codec.registerPacketType(TestMessageSizedString.class);
		codec.registerPacketType(TestMessageMethodSizedString.class);
		String enc;

		enc = codec.encodePacket(new TestMessageSizedString("Testing", 4));
		assertEquals("7,Testing4", enc);

		enc = codec.encodePacket(new TestMessageMethodSizedString("Testing2"));
		assertEquals("c,Testing2", enc);
	}

	@Test
	public void testCountedAnnot() throws PacketEncodeException {
		codec.registerPacketType(TestMessageCountedShortArray.class);
		String enc;

		enc = codec.encodePacket(
			new TestMessageCountedShortArray(0xbeef, (short) 0, (short) 1, (short) 2, (short) 3));
		assertEquals("4,0,1,2,3;beef", enc);
	}

	@Test
	public void testTypedAnnot() throws PacketEncodeException {
		codec.registerPacketType(TestMessageDynamicTyped.class);
		codec.registerPacketType(TestMessageDynamicTypedSubs.class);
		String enc;

		enc = codec.encodePacket(new TestMessageDynamicTyped(3));
		assertEquals("1,3", enc);

		enc = codec.encodePacket(new TestMessageDynamicTyped(4L));
		assertEquals("2,4", enc);

		enc = codec.encodePacket(
			new TestMessageDynamicTypedSubs(new TestMessageDynamicTypedSubs.IntTestMessage(3)));
		assertEquals("1,3", enc);

		enc = codec.encodePacket(
			new TestMessageDynamicTypedSubs(new TestMessageDynamicTypedSubs.LongTestMessage(4)));
		assertEquals("2,4", enc);
	}

	@Test
	public void testCollection() throws PacketEncodeException {
		codec.registerPacketType(TestMessageUnmeasuredCollection.class);
		codec.registerPacketType(TestMessageFullSpecColField.class);
		String enc;

		enc = codec.encodePacket(new TestMessageUnmeasuredCollection("Testing", 1, 2));
		assertEquals("2,7,Testing" + "1,1,1" + "1,1,2", enc);

		enc = codec.encodePacket(new TestMessageFullSpecColField(0, 1, 2, 3));
		assertEquals("0,1,2,3", enc);
	}

	@Test
	public void testLookahead() throws PacketEncodeException {
		codec.registerPacketType(TestMessageLookahead.class);
		String enc;

		enc = codec.encodePacket(new TestMessageLookahead(3));
		assertEquals("Int3", enc);

		enc = codec.encodePacket(new TestMessageLookahead(4L));
		assertEquals("Long4", enc);
	}

	@Test
	public void testDoubleTermed() throws PacketEncodeException {
		codec.registerPacketType(TestMessageDoubleTermed.class);
		String enc;

		enc = codec.encodePacket(new TestMessageDoubleTermed("Testing"));
		assertEquals("7,Testing,", enc);
	}

	@Test
	public void testFixedSize() throws PacketEncodeException {
		codec.registerPacketType(TestMessageFixedSize.class);
		String enc;

		enc = codec.encodePacket(new TestMessageFixedSize(0, 1, 2, 3));
		assertEquals("00000000000000010000000200000003", enc);
	}

	@Test
	public void testOptional() throws PacketEncodeException {
		codec.registerPacketType(TestMessageOptional.class);
		String enc;

		enc = codec.encodePacket(new TestMessageOptional("SomeString"));
		assertEquals("SomeString", enc);

		enc = codec.encodePacket(new TestMessageOptional("SomeString", 51));
		assertEquals("SomeString;33", enc);
	}

	@Test
	public void testEnum() throws PacketEncodeException {
		codec.registerPacketType(TestMessageEnum.class);
		String enc;

		enc = codec.encodePacket(new TestMessageEnum(TestEnum.ON, 51));
		assertEquals("ON33", enc);

		enc = codec.encodePacket(new TestMessageEnum(TestEnum.ONE, 51));
		assertEquals("ONE33", enc);
	}

	@Test
	public void testHexString() throws PacketEncodeException {
		codec.registerPacketType(TestMessageHexString.class);
		String enc;

		enc = codec.encodePacket(new TestMessageHexString("Testing"));
		assertEquals("54657374696e67", enc);
	}
}
