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
package ghidra.program.model.data;

import static org.junit.Assert.*;

import java.nio.charset.Charset;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.RenderUnicodeSettingsDefinition.RENDER_ENUM;
import ghidra.program.model.mem.ByteMemBufferImpl;

/**
 * Test rendering of various Char data types.
 * <p>
 * TODO: force the WideCharDataType instance's dataOrg to switch to 32bit.
 */
public class CharDataTypesRenderTest extends AbstractGTest {

	private ByteMemBufferImpl mb(boolean isBE, int... values) {
		GenericAddressSpace gas = new GenericAddressSpace("test", 32, AddressSpace.TYPE_RAM, 1);
		return new ByteMemBufferImpl(gas.getAddress(0), bytes(values), isBE);
	}

	private SettingsBuilder newset() {
		return new SettingsBuilder();
	}

	private CharDataType charDT = new CharDataType();
	private UnsignedCharDataType ucharDT = new UnsignedCharDataType();
	private WideCharDataType wcharDT = new WideCharDataType();
	private WideChar16DataType wchar16DT = new WideChar16DataType();
	private WideChar32DataType wchar32DT = new WideChar32DataType();
	private Charset thaiCS = Charset.forName("IBM-Thai");

	private static void assertContainsStr(String expectedSubstr, String actualStr) {
		assertTrue("Substring [" + expectedSubstr + "] is not present in actual string [" +
			actualStr + "]", actualStr.contains(expectedSubstr));
	}

	@Before
	public void setup() {
		assertNotNull(thaiCS);
	}

	@Test
	public void testSimpleASCIIChar() {
		//@formatter:off
		assertEquals("'a'", charDT.getRepresentation(mb(false, 'a'), newset(), charDT.getLength()));
		assertEquals("'a'", ucharDT.getRepresentation(mb(false, 'a'), newset(), ucharDT.getLength()));
		assertEquals("u'a'", wcharDT.getRepresentation(mb(false, 'a', 0), newset(), wcharDT.getLength()));
		assertEquals("u'a'", wchar16DT.getRepresentation(mb(false, 'a', 0), newset(), wchar16DT.getLength()));
		assertEquals("U'a'", wchar32DT.getRepresentation(mb(false, 'a', 0, 0, 0), newset(), wchar32DT.getLength()));
		//@formatter:on
	}

	@Test
	public void testWideCharsNonAscii() {
		// Test rendering a non-ascii, but valid ideographic character.
		// The literal const strings used below as the "expected" values
		// use java's escape method for encoding a unicode character, but rest
		// assured that the bytes in the literal string are the direct native unicode
		// values and not the '\', 'u', 'c', 'c', etc.
		ByteMemBufferImpl buf_thai = mb(false, 66);
		ByteMemBufferImpl buf_be16 = mb(true, 0xcc, 0x01);
		ByteMemBufferImpl buf_be32 = mb(true, 0, 0, 0xcc, 0x01);
		ByteMemBufferImpl buf_le1632 = mb(false, 0x01, 0xcc, 0, 0);

		//@formatter:off
		assertEquals("'\u0e01'", charDT.getRepresentation(buf_thai, newset().set(thaiCS), charDT.getLength()));
		assertEquals("u'\ucc01'", wcharDT.getRepresentation(buf_be16, newset(), wcharDT.getLength()));
		assertEquals("u'\ucc01'", wcharDT.getRepresentation(buf_le1632, newset(), wcharDT.getLength()));

		assertEquals("u'\ucc01'", wchar16DT.getRepresentation(buf_be16, newset(), wchar16DT.getLength()));
		assertEquals("u'\ucc01'", wchar16DT.getRepresentation(buf_le1632, newset(), wchar16DT.getLength()));

		assertEquals("U'\ucc01'", wchar32DT.getRepresentation(buf_be32, newset(), wchar32DT.getLength()));
		assertEquals("U'\ucc01'", wchar32DT.getRepresentation(buf_le1632, newset(), wchar32DT.getLength()));
		//@formatter:on
	}

	@Test
	public void testWideCharsNonAscii_EscSeq() {
		ByteMemBufferImpl buf_thai = mb(false, 66);
		ByteMemBufferImpl buf_be16 = mb(true, 0xcc, 0x01);
		ByteMemBufferImpl buf_be32 = mb(true, 0, 0, 0xcc, 0x01);
		ByteMemBufferImpl buf_le1632 = mb(false, 0x01, 0xcc, 0, 0);
		SettingsBuilder escseq = newset().set(RENDER_ENUM.ESC_SEQ);

		//@formatter:off
		assertContainsStr("'\\u0E01'", charDT.getRepresentation(buf_thai, newset().set(thaiCS).set(RENDER_ENUM.ESC_SEQ), charDT.getLength()));
		assertEquals("u'\\uCC01'", wcharDT.getRepresentation(buf_be16, escseq, wcharDT.getLength()));
		assertEquals("u'\\uCC01'", wcharDT.getRepresentation(buf_le1632, escseq, wcharDT.getLength()));

		assertEquals("u'\\uCC01'", wchar16DT.getRepresentation(buf_be16, escseq, wchar16DT.getLength()));
		assertEquals("u'\\uCC01'", wchar16DT.getRepresentation(buf_le1632, escseq, wchar16DT.getLength()));

		assertEquals("U'\\uCC01'", wchar32DT.getRepresentation(buf_be32, escseq, wchar32DT.getLength()));
		assertEquals("U'\\uCC01'", wchar32DT.getRepresentation(buf_le1632, escseq, wchar32DT.getLength()));
		//@formatter:on
	}

	@Test
	public void testNonAsciiCharset() {
		// in thai charset, byte 73 ('I') maps to the normal ascii char '['
		String result =
			charDT.getRepresentation(mb(false, 73), newset().set(thaiCS), charDT.getLength());

		assertEquals("'['", result);
	}

	@Test
	public void testEscapeSequenceRender_singlebyte_to_multibyte() {
		// in thai charset, byte 66 ('B') maps to a 'n' looking thing with a line
		String result = charDT.getRepresentation(mb(false, 66),
			newset().set(thaiCS).set(RENDER_ENUM.ESC_SEQ), charDT.getLength());

		assertContainsStr("'\\u0E01'", result);
	}

	@Test
	public void testRender_invalid_values() {
		// With us-ascii charset, bytes values above 0x7f are invalid.
		// With utf-16, 0xD800-0xDFFF are reserved
		// With utf-32, not all possible integer values are valid unicode codepoints.
		// Test that an invalid value forces the render mode to byte_seq.

		ByteMemBufferImpl buf8 = mb(false, 0x85);
		ByteMemBufferImpl buf16_be = mb(true, 0xd8, 0x00);
		ByteMemBufferImpl buf32 = mb(false, 0xaa, 0xaa, 0xaa, 0xaa);

		SettingsBuilder normset = newset();
		SettingsBuilder escseq = newset().set(RENDER_ENUM.ESC_SEQ);
		SettingsBuilder byteseq = newset().set(RENDER_ENUM.BYTE_SEQ);

		// wchar32
		String result = wchar32DT.getRepresentation(buf32, normset, wchar32DT.getLength());
		assertEquals("AAh,AAh,AAh,AAh", result);

		result = wchar32DT.getRepresentation(buf32, escseq, wchar32DT.getLength());
		assertEquals("AAh,AAh,AAh,AAh", result);

		result = wchar32DT.getRepresentation(buf32, byteseq, wchar32DT.getLength());
		assertEquals("AAh,AAh,AAh,AAh", result);

		// wchar16
		result = wchar16DT.getRepresentation(buf16_be, normset, wchar16DT.getLength());
		assertEquals("D8h,00h", result);

		result = wchar16DT.getRepresentation(buf16_be, escseq, wchar16DT.getLength());
		assertEquals("D8h,00h", result);

		result = wchar16DT.getRepresentation(buf16_be, byteseq, wchar16DT.getLength());
		assertEquals("D8h,00h", result);

		// charDT
		result = charDT.getRepresentation(buf8, normset, charDT.getLength());
		assertEquals("85h", result);

		result = charDT.getRepresentation(buf8, escseq, charDT.getLength());
		assertEquals("85h", result);

		result = charDT.getRepresentation(buf8, byteseq, charDT.getLength());
		assertEquals("85h", result);
	}

	@Test
	public void testEscapeSequenceRender_literal_unicode_replacement_char() {
		// char literal 0xfffd.

		String result =
			wchar16DT.getRepresentation(mb(false, 0xfd, 0xff), newset(), wchar16DT.getLength());
		assertEquals("u'\uFFFD'", result);

		result = wchar16DT.getRepresentation(mb(false, 0xfd, 0xff),
			newset().set(RENDER_ENUM.ESC_SEQ), wchar16DT.getLength());
		assertEquals("u'\\uFFFD'", result);

		result = wchar16DT.getRepresentation(mb(false, 0xfd, 0xff),
			newset().set(RENDER_ENUM.BYTE_SEQ), wchar16DT.getLength());
		assertEquals("FDh,FFh", result);
	}
}
