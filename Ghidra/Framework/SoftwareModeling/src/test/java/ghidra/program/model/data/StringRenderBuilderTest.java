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

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.program.model.data.RenderUnicodeSettingsDefinition.RENDER_ENUM;

public class StringRenderBuilderTest extends AbstractGTest {
	private static final Charset US_ASCII = StandardCharsets.US_ASCII;
	private static final Charset UTF8 = StandardCharsets.UTF_8;
	private static final Charset UTF16 = StandardCharsets.UTF_16;
	private static final Charset UTF32 = Charset.forName("UTF-32");

	private ByteBuffer bb(int... values) {
		return ByteBuffer.wrap(bytes(values));
	}

	@Test
	public void testEmptyString() {
		StringRenderBuilder srb =
			new StringRenderBuilder(US_ASCII, 1, StringRenderBuilder.DOUBLE_QUOTE);
		String emptyString = srb.build();
		assertEquals("\"\"", emptyString);
	}

	@Test
	public void testEmptyWChar2String() {
		StringRenderBuilder srb =
			new StringRenderBuilder(UTF16, 2, StringRenderBuilder.DOUBLE_QUOTE);
		String emptyString = srb.build();
		assertEquals("u\"\"", emptyString);
	}

	@Test
	public void testEmptyWChar4String() {
		StringRenderBuilder srb =
			new StringRenderBuilder(UTF32, 4, StringRenderBuilder.DOUBLE_QUOTE);
		String emptyString = srb.build();
		assertEquals("U\"\"", emptyString);
	}

	@Test
	public void testEmptyStringWithNulls() {
		ByteBuffer bb = bb(0, 0, 0);
		StringRenderBuilder srb =
			new StringRenderBuilder(US_ASCII, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ALL, true);
		String emptyString = srb.build();
		assertEquals("\"\"", emptyString);
	}

	@Test
	public void testEmptyStringWithNullsNoTrim() {
		ByteBuffer bb = bb(0, 0, 0);
		StringRenderBuilder srb =
			new StringRenderBuilder(US_ASCII, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ALL, false);
		String s = srb.build();
		assertEquals("00h,00h,00h", s);
	}

	@Test
	public void testInteriorNulls() {
		ByteBuffer bb = bb('t', 'e', 0, 's', 't', 0);
		StringRenderBuilder srb =
			new StringRenderBuilder(US_ASCII, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("\"te\\0st\"", s);
	}

	@Test
	public void testSimpleString() {
		ByteBuffer bb = bb('t', 'e', 's', 't');
		StringRenderBuilder srb =
			new StringRenderBuilder(US_ASCII, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("\"test\"", s);
	}

	@Test
	public void testStandardEscapedChars() {
		ByteBuffer bb = bb('t', 'e', 's', 't', '\n', '\t', '\r');
		StringRenderBuilder srb =
			new StringRenderBuilder(US_ASCII, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("\"test\\n\\t\\r\"", s);
	}

	@Test
	public void testQuotedQuotesChars() {
		ByteBuffer bb = bb('t', 'e', 's', 't', '"', '1', '2', '3');
		StringRenderBuilder srb =
			new StringRenderBuilder(US_ASCII, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("\"test\\\"123\"", s);
	}

	@Test
	public void testSingleQuoteChars() {
		ByteBuffer bb = bb('t', 'e', 's', 't', '\'', '1', '2', '3');
		StringRenderBuilder srb =
			new StringRenderBuilder(US_ASCII, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("\"test'123\"", s);
	}

	@Test
	public void testSimpleStringWithTrailingNulls() {
		ByteBuffer bb = bb('t', 'e', 's', 't', 0, 0, 0);
		StringRenderBuilder srb =
			new StringRenderBuilder(US_ASCII, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("\"test\"", s);
	}

	@Test
	public void testSimpleStringWithTrailingNullsNoTrim() {
		ByteBuffer bb = bb('t', 'e', 's', 't', 0, 0, 0);
		StringRenderBuilder srb =
			new StringRenderBuilder(US_ASCII, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ALL, false);
		String s = srb.build();
		assertEquals("\"test\\0\\0\\0\"", s);
	}

	@Test
	public void testUtf8String() {
		ByteBuffer bb = bb(0xE1, 0x84, 0xA2); // should decode to \u1122
		StringRenderBuilder srb =
			new StringRenderBuilder(UTF8, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("u8\"\u1122\"", s);
	}

	@Test
	public void testUtf8NoRenderNonLatinString() {
		ByteBuffer bb = bb(0xE1, 0x84, 0xA2); // should decode to \u1122
		StringRenderBuilder srb =
			new StringRenderBuilder(UTF8, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ESC_SEQ, true);
		String s = srb.build();
		assertEquals("u8\"\\u1122\"", s); // <- result is \ u 1122
	}

	@Test
	public void testBadBytes_USASCII() {
		ByteBuffer bb = bb('t', 'e', 's', 't', 0x80);
		StringRenderBuilder srb =
			new StringRenderBuilder(US_ASCII, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("\"test\",80h", s);
	}

	@Test
	public void testBadBytes_USASCII2() {
		// bad bytes in interior of string, switching modes
		ByteBuffer bb = bb('t', 'e', 0x80, 's', 't');
		StringRenderBuilder srb =
			new StringRenderBuilder(US_ASCII, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("\"te\",80h,\"st\"", s);
	}

	@Test
	public void testBadBytes_USASCII3() {
		// bad bytes at beginning of string
		ByteBuffer bb = bb(0x80, 't', 'e', 's', 't');
		StringRenderBuilder srb =
			new StringRenderBuilder(US_ASCII, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("80h,\"test\"", s);
	}

	@Test
	public void testTruncatedUtf8() {
		ByteBuffer bb = bb('t', 'e', 's', 't', 0xE1, 0x84);
		StringRenderBuilder srb =
			new StringRenderBuilder(UTF8, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("u8\"test\",E1h,84h", s);
	}

	@Test
	public void testUtf16() {
		ByteBuffer bb = bb('t', 0, 'e', 0, 's', 0, 't', 0);
		StringRenderBuilder srb =
			new StringRenderBuilder(StandardCharsets.UTF_16LE, 2, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("u\"test\"", s);
	}

	@Test
	public void testUtf16BOM_LE() {
		ByteBuffer bb = bb(0xff, 0xfe, 't', 0, 'e', 0, 's', 0, 't', 0);
		StringRenderBuilder srb =
			new StringRenderBuilder(StandardCharsets.UTF_16LE, 2, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("u\"\\uFEFFtest\"", s);
	}

	@Test
	public void testUtf32BOM_LE() {
		// This test demonstrates the inconsistency of decoding a BOM in UTF-16 vs UTF-32
		// UTF-16 charset impls will preserve the BOM in the result, whereas the UTF-32 does not.
		// This probably isn't a big deal as BOMs aren't used frequently (?)
		ByteBuffer bb =
			bb(0xff, 0xfe, 0, 0, 't', 0, 0, 0, 'e', 0, 0, 0, 's', 0, 0, 0, 't', 0, 0, 0);
		StringRenderBuilder srb = new StringRenderBuilder(Charset.forName("UTF-32LE"), 4,
			StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("U\"test\"", s);
	}
}
