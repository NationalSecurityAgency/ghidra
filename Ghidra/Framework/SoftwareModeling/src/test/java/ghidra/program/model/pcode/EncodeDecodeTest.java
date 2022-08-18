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
package ghidra.program.model.pcode;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;
import static org.junit.Assert.*;

import java.io.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.*;

public class EncodeDecodeTest extends AbstractGenericTest {

	private AddressFactory addrFactory;

	private void testSignedAttributes(Encoder encoder, Decoder decoder)
			throws DecoderException, IOException

	{
		encoder.openElement(ELEM_ADDR);
		encoder.writeSignedInteger(ATTRIB_ALIGN, 3);	// 7-bits
		encoder.writeSignedInteger(ATTRIB_BIGENDIAN, -0x100);	// 14-bits
		encoder.writeSignedInteger(ATTRIB_CONSTRUCTOR, 0x1fffff);	// 21-bits
		encoder.writeSignedInteger(ATTRIB_DESTRUCTOR, -0xabcdefa);	// 28-bits
		encoder.writeSignedInteger(ATTRIB_EXTRAPOP, 0x300000000L);	// 35-bits
		encoder.writeSignedInteger(ATTRIB_FORMAT, -0x30101010101L);	// 42-bits
		encoder.writeSignedInteger(ATTRIB_ID, 0x123456789011L);	// 49-bits
		encoder.writeSignedInteger(ATTRIB_INDEX, -0xf0f0f0f0f0f0f0L);	// 56-bits
		encoder.writeSignedInteger(ATTRIB_METATYPE, 0x7fffffffffffffffL);	// 63-bits
		encoder.closeElement(ELEM_ADDR);
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		encoder.writeTo(outStream);
		ByteArrayInputStream inStream = new ByteArrayInputStream(outStream.toByteArray());
		decoder.open(1 << 20, "testSignedAttributes");
		decoder.ingestStream(inStream);
		decoder.endIngest();
		int el = decoder.openElement(ELEM_ADDR);
		int flags = 0;
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == ATTRIB_ALIGN.id()) {
				long val = decoder.readSignedInteger();
				flags |= 1;
				assertEquals(val, 3);
			}
			else if (attribId == ATTRIB_BIGENDIAN.id()) {
				long val = decoder.readSignedInteger();
				flags |= 2;
				assertEquals(val, -0x100);
			}
			else if (attribId == ATTRIB_CONSTRUCTOR.id()) {
				long val = decoder.readSignedInteger();
				flags |= 4;
				assertEquals(val, 0x1fffff);
			}
			else if (attribId == ATTRIB_DESTRUCTOR.id()) {
				long val = decoder.readSignedInteger();
				flags |= 8;
				assertEquals(val, -0xabcdefa);
			}
			else if (attribId == ATTRIB_EXTRAPOP.id()) {
				long val = decoder.readSignedInteger();
				flags |= 0x10;
				assertEquals(val, 0x300000000L);
			}
			else if (attribId == ATTRIB_FORMAT.id()) {
				long val = decoder.readSignedInteger();
				flags |= 0x20;
				assertEquals(val, -0x30101010101L);
			}
			else if (attribId == ATTRIB_ID.id()) {
				long val = decoder.readSignedInteger();
				flags |= 0x40;
				assertEquals(val, 0x123456789011L);
			}
			else if (attribId == ATTRIB_INDEX.id()) {
				long val = decoder.readSignedInteger();
				flags |= 0x80;
				assertEquals(val, -0xf0f0f0f0f0f0f0L);
			}
			else if (attribId == ATTRIB_METATYPE.id()) {
				long val = decoder.readSignedInteger();
				flags |= 0x100;
				assertEquals(val, 0x7fffffffffffffffL);
			}
		}
		decoder.closeElement(el);
		assertEquals(flags, 0x1ff);
	}

	private void testUnsignedAttributes(Encoder encoder, Decoder decoder)
			throws DecoderException, IOException

	{
		encoder.openElement(ELEM_ADDR);
		encoder.writeUnsignedInteger(ATTRIB_ALIGN, 3);	// 7-bits
		encoder.writeUnsignedInteger(ATTRIB_BIGENDIAN, 0x100);	// 14-bits
		encoder.writeUnsignedInteger(ATTRIB_CONSTRUCTOR, 0x1fffff);	// 21-bits
		encoder.writeUnsignedInteger(ATTRIB_DESTRUCTOR, 0xabcdefa);	// 28-bits
		encoder.writeUnsignedInteger(ATTRIB_EXTRAPOP, 0x300000000L);	// 35-bits
		encoder.writeUnsignedInteger(ATTRIB_FORMAT, 0x30101010101L);	// 42-bits
		encoder.writeUnsignedInteger(ATTRIB_ID, 0x123456789011L);	// 49-bits
		encoder.writeUnsignedInteger(ATTRIB_INDEX, 0xf0f0f0f0f0f0f0L);	// 56-bits
		encoder.writeUnsignedInteger(ATTRIB_METATYPE, 0x7fffffffffffffffL);	// 63-bits
		encoder.writeUnsignedInteger(ATTRIB_MODEL, 0x8000000000000000L);	// 64-bits
		encoder.closeElement(ELEM_ADDR);
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		encoder.writeTo(outStream);
		ByteArrayInputStream inStream = new ByteArrayInputStream(outStream.toByteArray());
		decoder.open(1 << 20, "testUnsignedAttributes");
		decoder.ingestStream(inStream);
		decoder.endIngest();
		int el = decoder.openElement(ELEM_ADDR);
		long val = decoder.readUnsignedInteger(ATTRIB_ALIGN);
		assertEquals(val, 3);
		val = decoder.readUnsignedInteger(ATTRIB_BIGENDIAN);
		assertEquals(val, 0x100);
		val = decoder.readUnsignedInteger(ATTRIB_CONSTRUCTOR);
		assertEquals(val, 0x1fffff);
		val = decoder.readUnsignedInteger(ATTRIB_DESTRUCTOR);
		assertEquals(val, 0xabcdefa);
		val = decoder.readUnsignedInteger(ATTRIB_EXTRAPOP);
		assertEquals(val, 0x300000000L);
		val = decoder.readUnsignedInteger(ATTRIB_FORMAT);
		assertEquals(val, 0x30101010101L);
		val = decoder.readUnsignedInteger(ATTRIB_ID);
		assertEquals(val, 0x123456789011L);
		val = decoder.readUnsignedInteger(ATTRIB_INDEX);
		assertEquals(val, 0xf0f0f0f0f0f0f0L);
		val = decoder.readUnsignedInteger(ATTRIB_METATYPE);
		assertEquals(val, 0x7fffffffffffffffL);
		val = decoder.readUnsignedInteger(ATTRIB_MODEL);
		assertEquals(val, 0x8000000000000000L);
		decoder.closeElement(el);
	}

	private void testAttributes(Encoder encoder, Decoder decoder)
			throws DecoderException, IOException

	{
		encoder.openElement(ELEM_DATA);
		encoder.writeBool(ATTRIB_ALIGN, true);
		encoder.writeBool(ATTRIB_BIGENDIAN, false);
		AddressSpace spc = addrFactory.getDefaultAddressSpace();
		encoder.writeSpace(ATTRIB_SPACE, spc);
		encoder.writeString(ATTRIB_VAL, "");	// Empty string
		encoder.writeString(ATTRIB_VALUE, "hello");
		encoder.writeString(ATTRIB_CONSTRUCTOR, "<<\u20ac>>&\"bl a  h\'\\bleh\n\t");
		String longString =
			"one to three four five six seven eight nine ten eleven twelve thirteen " +
				"fourteen fifteen sixteen seventeen eighteen nineteen twenty twenty one " +
				"blahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblah";
		encoder.writeString(ATTRIB_DESTRUCTOR, longString);
		encoder.closeElement(ELEM_DATA);
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		encoder.writeTo(outStream);
		ByteArrayInputStream inStream = new ByteArrayInputStream(outStream.toByteArray());
		decoder.open(1 << 20, "testAttributes");
		decoder.ingestStream(inStream);
		decoder.endIngest();
		int el = decoder.openElement(ELEM_DATA);
		boolean bval = decoder.readBool(ATTRIB_ALIGN);
		assertTrue(bval);
		bval = decoder.readBool(ATTRIB_BIGENDIAN);
		assertTrue(!bval);
		spc = decoder.readSpace(ATTRIB_SPACE);
		assertEquals(spc, addrFactory.getDefaultAddressSpace());
		String val = decoder.readString(ATTRIB_VAL);
		assertEquals(val, "");
		val = decoder.readString(ATTRIB_VALUE);
		assertEquals(val, "hello");
		val = decoder.readString(ATTRIB_CONSTRUCTOR);
		assertEquals(val, "<<\u20ac>>&\"bl a  h\'\\bleh\n\t");
		val = decoder.readString(ATTRIB_DESTRUCTOR);
		assertEquals(val, longString);
		decoder.closeElement(el);
	}

	private void testHierarchy(Encoder encoder, Decoder decoder)
			throws IOException, DecoderException

	{
		encoder.openElement(ELEM_DATA);		// el1
		encoder.writeBool(ATTRIB_CONTENT, true);
		encoder.openElement(ELEM_INPUT);		// el2
		encoder.openElement(ELEM_OUTPUT);		// el3
		encoder.writeSignedInteger(ATTRIB_ID, 0x1000);
		encoder.openElement(ELEM_DATA);		// el4
		encoder.openElement(ELEM_DATA);		// el5
		encoder.openElement(ELEM_OFF);		// el6
		encoder.closeElement(ELEM_OFF);
		encoder.openElement(ELEM_OFF);		// el6
		encoder.writeString(ATTRIB_ID, "blahblah");
		encoder.closeElement(ELEM_OFF);
		encoder.openElement(ELEM_OFF);		// el6
		encoder.closeElement(ELEM_OFF);
		encoder.closeElement(ELEM_DATA);		// close el5
		encoder.closeElement(ELEM_DATA);		// close el4
		encoder.openElement(ELEM_SYMBOL);		// skip4
		encoder.writeUnsignedInteger(ATTRIB_ID, 17);
		encoder.openElement(ELEM_TARGET);		// skip5
		encoder.closeElement(ELEM_TARGET);		// close skip5
		encoder.closeElement(ELEM_SYMBOL);		// close skip4
		encoder.closeElement(ELEM_OUTPUT);		// close el3
		encoder.closeElement(ELEM_INPUT);		// close el2
		encoder.openElement(ELEM_INPUT);		// el2
		encoder.closeElement(ELEM_INPUT);
		encoder.openElement(ELEM_INPUT);		// el2
		encoder.closeElement(ELEM_INPUT);
		encoder.openElement(ELEM_INPUT);		// el2
		encoder.closeElement(ELEM_INPUT);
		encoder.openElement(ELEM_INPUT);		// el2
		encoder.closeElement(ELEM_INPUT);
		encoder.openElement(ELEM_INPUT);		// el2
		encoder.closeElement(ELEM_INPUT);
		encoder.openElement(ELEM_INPUT);		// el2
		encoder.closeElement(ELEM_INPUT);
		encoder.closeElement(ELEM_DATA);		// close el1
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		encoder.writeTo(outStream);
		ByteArrayInputStream inStream = new ByteArrayInputStream(outStream.toByteArray());
		decoder.open(1 << 20, "testHierarchy");
		decoder.ingestStream(inStream);
		decoder.endIngest();
		int el1 = decoder.openElement(ELEM_DATA);
		// Skip over the bool
		int el2 = decoder.openElement(ELEM_INPUT);
		int el3 = decoder.openElement(ELEM_OUTPUT);
		int val = (int) decoder.readSignedInteger(ATTRIB_ID);
		assertEquals(val, 0x1000);
		int el4 = decoder.peekElement();
		assertEquals(el4, ELEM_DATA.id());
		decoder.openElement();
		int el5 = decoder.openElement();
		assertEquals(el5, ELEM_DATA.id());
		int el6 = decoder.openElement(ELEM_OFF);
		decoder.closeElement(el6);
		el6 = decoder.openElement(ELEM_OFF);
		decoder.closeElement(el6);
		el6 = decoder.openElement(ELEM_OFF);
		decoder.closeElement(el6);
		decoder.closeElement(el5);
		decoder.closeElement(el4);
		decoder.closeElementSkipping(el3);
		decoder.closeElement(el2);
		el2 = decoder.openElement(ELEM_INPUT);
		decoder.closeElement(el2);
		el2 = decoder.openElement(ELEM_INPUT);
		decoder.closeElement(el2);
		decoder.closeElementSkipping(el1);
	}

	private void testUnexpectedEof(Encoder encoder, Decoder decoder) throws IOException

	{
		encoder.openElement(ELEM_DATA);
		encoder.openElement(ELEM_INPUT);
		encoder.writeString(ATTRIB_NAME, "hello");
		encoder.closeElement(ELEM_INPUT);
		boolean sawUnexpectedError = false;
		try {
			ByteArrayOutputStream outStream = new ByteArrayOutputStream();
			encoder.writeTo(outStream);
			ByteArrayInputStream inStream = new ByteArrayInputStream(outStream.toByteArray());
			decoder.open(1 << 20, "testAttributes");
			decoder.ingestStream(inStream);
			decoder.endIngest();
			int el1 = decoder.openElement(ELEM_DATA);
			int el2 = decoder.openElement(ELEM_INPUT);
			decoder.closeElement(el2);
			decoder.closeElement(el1);
		}
		catch (DecoderException err) {
			sawUnexpectedError = true;
		}
		assertTrue(sawUnexpectedError);
	}

	public void testNoremaining(Encoder encoder, Decoder decoder)
			throws IOException, DecoderException

	{
		encoder.openElement(ELEM_INPUT);
		encoder.openElement(ELEM_OFF);
		encoder.closeElement(ELEM_OFF);
		encoder.closeElement(ELEM_INPUT);
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		encoder.writeTo(outStream);
		ByteArrayInputStream inStream = new ByteArrayInputStream(outStream.toByteArray());
		decoder.open(1 << 20, "testNoremaining");
		decoder.ingestStream(inStream);
		decoder.endIngest();
		decoder.openElement(ELEM_INPUT);
		int el2 = decoder.openElement(ELEM_OFF);
		decoder.closeElement(el2);
		boolean sawNoRemaining = false;
		try {
			el2 = decoder.openElement(ELEM_OFF);
		}
		catch (DecoderException err) {
			sawNoRemaining = true;
		}
		assertTrue(sawNoRemaining);
	}

	private void testOpenmismatch(Encoder encoder, Decoder decoder)
			throws IOException, DecoderException

	{
		encoder.openElement(ELEM_INPUT);
		encoder.openElement(ELEM_OFF);
		encoder.closeElement(ELEM_OFF);
		encoder.closeElement(ELEM_INPUT);
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		encoder.writeTo(outStream);
		ByteArrayInputStream inStream = new ByteArrayInputStream(outStream.toByteArray());
		decoder.open(1 << 20, "testOpenmismatch");
		decoder.ingestStream(inStream);
		decoder.endIngest();
		decoder.openElement(ELEM_INPUT);
		boolean sawOpenMismatch = false;
		try {
			decoder.openElement(ELEM_OUTPUT);
		}
		catch (DecoderException err) {
			sawOpenMismatch = true;
		}
		assertTrue(sawOpenMismatch);
	}

	private void testClosemismatch(Encoder encoder, Decoder decoder)
			throws IOException, DecoderException

	{
		encoder.openElement(ELEM_INPUT);
		encoder.openElement(ELEM_OFF);
		encoder.closeElement(ELEM_OFF);
		encoder.closeElement(ELEM_INPUT);
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		encoder.writeTo(outStream);
		ByteArrayInputStream inStream = new ByteArrayInputStream(outStream.toByteArray());
		decoder.open(1 << 20, "testClosemismatch");
		decoder.ingestStream(inStream);
		decoder.endIngest();
		int el1 = decoder.openElement(ELEM_INPUT);
		boolean sawCloseMismatch = false;
		try {
			decoder.closeElement(el1);
		}
		catch (DecoderException err) {
			sawCloseMismatch = true;
		}
		assertTrue(sawCloseMismatch);
	}

	@Before
	public void setUp() {
		AddressSpace spaces[] = new AddressSpace[4];
		spaces[0] = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 2);
		spaces[1] = new GenericAddressSpace("register", 32, AddressSpace.TYPE_REGISTER, 3);
		spaces[2] = new GenericAddressSpace("const", 32, AddressSpace.TYPE_CONSTANT, 0);
		spaces[3] = new GenericAddressSpace("unique", 32, AddressSpace.TYPE_UNIQUE, 1);

		addrFactory = new DefaultAddressFactory(spaces);
	}

	@Test
	public void testMarshalSignedPacked() throws DecoderException, IOException {
		PackedEncode encoder = new PackedEncode();
		encoder.clear();
		PackedDecode decoder = new PackedDecode(addrFactory);
		testSignedAttributes(encoder, decoder);
	}

	@Test
	public void marshalUnsignedPacked() throws DecoderException, IOException {
		PackedEncode encoder = new PackedEncode();
		encoder.clear();
		PackedDecode decoder = new PackedDecode(addrFactory);
		testUnsignedAttributes(encoder, decoder);
	}

	@Test
	public void marshalAttribsPacked() throws DecoderException, IOException {
		PackedEncode encoder = new PackedEncode();
		encoder.clear();
		PackedDecode decoder = new PackedDecode(addrFactory);
		testAttributes(encoder, decoder);
	}

	@Test
	public void marshalHierarchyPacked() throws DecoderException, IOException {
		PackedEncode encoder = new PackedEncode();
		encoder.clear();
		PackedDecode decoder = new PackedDecode(addrFactory);
		testHierarchy(encoder, decoder);
	}

	@Test
	public void marshalUnexpectedPacked() throws IOException {
		PackedEncode encoder = new PackedEncode();
		encoder.clear();
		PackedDecode decoder = new PackedDecode(addrFactory);
		testUnexpectedEof(encoder, decoder);
	}

	@Test
	public void marshalNoremainingPacked() throws IOException, DecoderException {
		PackedEncode encoder = new PackedEncode();
		encoder.clear();
		PackedDecode decoder = new PackedDecode(addrFactory);
		testNoremaining(encoder, decoder);
	}

	@Test
	public void marshalOpenmismatchPacked() throws IOException, DecoderException {
		PackedEncode encoder = new PackedEncode();
		encoder.clear();
		PackedDecode decoder = new PackedDecode(addrFactory);
		testOpenmismatch(encoder, decoder);
	}

	@Test
	public void marshalClosemismatchPacked() throws IOException, DecoderException {
		PackedEncode encoder = new PackedEncode();
		encoder.clear();
		PackedDecode decoder = new PackedDecode(addrFactory);
		testClosemismatch(encoder, decoder);
	}

	@Test
	public void marshalBufferpad() throws IOException, DecoderException {
		assertEquals(LinkedByteBuffer.BUFFER_SIZE, 1024);
		PackedEncode encoder = new PackedEncode();
		encoder.clear();
		encoder.openElement(ELEM_INPUT);		// 1-byte
		for (int i = 0; i < 511; ++i) {
			encoder.writeBool(ATTRIB_CONTENT, (i & 1) == 0);
		}
		encoder.closeElement(ELEM_INPUT);
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		encoder.writeTo(outStream);
		byte[] bytesOut = outStream.toByteArray();
		assertEquals(bytesOut.length, 1024);		// Encoding should exactly fill one buffer
		ByteArrayInputStream inStream = new ByteArrayInputStream(bytesOut);
		PackedDecode decoder = new PackedDecode(addrFactory);
		decoder.open(1 << 20, "marshalBufferpad");
		decoder.ingestStream(inStream);
		decoder.endIngest();
		int el = decoder.openElement(ELEM_INPUT);
		for (int i = 0; i < 511; ++i) {
			int attribId = decoder.getNextAttributeId();
			assertEquals(attribId, ATTRIB_CONTENT.id());
			boolean val = decoder.readBool();
			assertEquals(val, (i & 1) == 0);
		}
		int nextel = decoder.peekElement();
		assertEquals(nextel, 0);
		decoder.closeElement(el);
	}

}
