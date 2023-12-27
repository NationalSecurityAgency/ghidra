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
import java.nio.charset.StandardCharsets;

import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.program.model.data.RenderUnicodeSettingsDefinition.RENDER_ENUM;

public class StringRenderBuilderTest extends AbstractGTest {

	private ByteBuffer bb(int... values) {
		return ByteBuffer.wrap(bytes(values));
	}

	@Test
	public void testEmptyString() {
		StringRenderBuilder srb =
			new StringRenderBuilder(false, 1, StringRenderBuilder.DOUBLE_QUOTE);
		String emptyString = srb.build();
		assertEquals("\"\"", emptyString);
	}

	@Test
	public void testEmptyWChar2String() {
		StringRenderBuilder srb =
			new StringRenderBuilder(true, 2, StringRenderBuilder.DOUBLE_QUOTE);
		String emptyString = srb.build();
		assertEquals("u\"\"", emptyString);
	}

	@Test
	public void testEmptyWChar4String() {
		StringRenderBuilder srb =
			new StringRenderBuilder(true, 4, StringRenderBuilder.DOUBLE_QUOTE);
		String emptyString = srb.build();
		assertEquals("U\"\"", emptyString);
	}

	@Test
	public void testEmptyStringWithNulls() {
		ByteBuffer bb = bb(0, 0, 0);
		StringRenderBuilder srb =
			new StringRenderBuilder(false, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, StandardCharsets.US_ASCII, RENDER_ENUM.ALL, true);
		String emptyString = srb.build();
		assertEquals("\"\"", emptyString);
	}

	@Test
	public void testEmptyStringWithNullsNoTrim() {
		ByteBuffer bb = bb(0, 0, 0);
		StringRenderBuilder srb =
			new StringRenderBuilder(false, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, StandardCharsets.US_ASCII, RENDER_ENUM.ALL, false);
		String s = srb.build();
		assertEquals("\"\\0\\0\\0\"", s);
	}

	@Test
	public void testInteriorNulls() {
		ByteBuffer bb = bb('t', 'e', 0, 's', 't', 0);
		StringRenderBuilder srb =
			new StringRenderBuilder(false, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, StandardCharsets.US_ASCII, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("\"te\\0st\"", s);
	}

	@Test
	public void testSimpleString() {
		ByteBuffer bb = bb('t', 'e', 's', 't');
		StringRenderBuilder srb =
			new StringRenderBuilder(false, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, StandardCharsets.US_ASCII, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("\"test\"", s);
	}

	@Test
	public void testStandardEscapedChars() {
		ByteBuffer bb = bb('t', 'e', 's', 't', '\n', '\t', '\r');
		StringRenderBuilder srb =
			new StringRenderBuilder(false, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, StandardCharsets.US_ASCII, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("\"test\\n\\t\\r\"", s);
	}

	@Test
	public void testQuotedQuotesChars() {
		ByteBuffer bb = bb('t', 'e', 's', 't', '"', '1', '2', '3');
		StringRenderBuilder srb =
			new StringRenderBuilder(false, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, StandardCharsets.US_ASCII, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("\"test\\\"123\"", s);
	}

	@Test
	public void testSingleQuoteChars() {
		ByteBuffer bb = bb('t', 'e', 's', 't', '\'', '1', '2', '3');
		StringRenderBuilder srb =
			new StringRenderBuilder(false, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, StandardCharsets.US_ASCII, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("\"test'123\"", s);
	}

	@Test
	public void testSimpleStringWithTrailingNulls() {
		ByteBuffer bb = bb('t', 'e', 's', 't', 0, 0, 0);
		StringRenderBuilder srb =
			new StringRenderBuilder(false, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, StandardCharsets.US_ASCII, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("\"test\"", s);
	}

	@Test
	public void testSimpleStringWithTrailingNullsNoTrim() {
		ByteBuffer bb = bb('t', 'e', 's', 't', 0, 0, 0);
		StringRenderBuilder srb =
			new StringRenderBuilder(false, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, StandardCharsets.US_ASCII, RENDER_ENUM.ALL, false);
		String s = srb.build();
		assertEquals("\"test\\0\\0\\0\"", s);
	}

	@Test
	public void testUtf8String() {
		ByteBuffer bb = bb(0xE1, 0x84, 0xA2); // should decode to \u1122
		StringRenderBuilder srb =
			new StringRenderBuilder(true, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, StandardCharsets.UTF_8, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("u8\"\u1122\"", s);
	}

	@Test
	public void testUtf8NoRenderNonLatinString() {
		ByteBuffer bb = bb(0xE1, 0x84, 0xA2); // should decode to \u1122
		StringRenderBuilder srb =
			new StringRenderBuilder(true, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, StandardCharsets.UTF_8, RENDER_ENUM.ESC_SEQ, true);
		String s = srb.build();
		assertEquals("u8\"\\u1122\"", s); // <- result is \ u 1122
	}

	@Test
	public void testBadBytes_USASCII() {
		ByteBuffer bb = bb('t', 'e', 's', 't', 0x80);
		StringRenderBuilder srb =
			new StringRenderBuilder(false, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, StandardCharsets.US_ASCII, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("\"test\",80h", s);
	}

	@Test
	public void testBadBytes_USASCII2() {
		// bad bytes in interior of string, switching modes
		ByteBuffer bb = bb('t', 'e', 0x80, 's', 't');
		StringRenderBuilder srb =
			new StringRenderBuilder(false, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, StandardCharsets.US_ASCII, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("\"te\",80h,\"st\"", s);
	}

	@Test
	public void testBadBytes_USASCII3() {
		// bad bytes at beginning of string
		ByteBuffer bb = bb(0x80, 't', 'e', 's', 't');
		StringRenderBuilder srb =
			new StringRenderBuilder(false, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, StandardCharsets.US_ASCII, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("80h,\"test\"", s);
	}

	@Test
	public void testTruncatedUtf8() {
		ByteBuffer bb = bb('t', 'e', 's', 't', 0xE1, 0x84);
		StringRenderBuilder srb =
			new StringRenderBuilder(true, 1, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, StandardCharsets.UTF_8, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("u8\"test\",E1h,84h", s);
	}

	@Test
	public void testUtf16() {
		ByteBuffer bb = bb('t', 0, 'e', 0, 's', 0, 't', 0);
		StringRenderBuilder srb =
			new StringRenderBuilder(true, 2, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, StandardCharsets.UTF_16LE, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("u\"test\"", s);
	}

	@Test
	public void testUtf16BOM_LE() {
		ByteBuffer bb = bb(0xff, 0xfe, 't', 0, 'e', 0, 's', 0, 't', 0);
		StringRenderBuilder srb =
			new StringRenderBuilder(true, 2, StringRenderBuilder.DOUBLE_QUOTE);
		srb.decodeBytesUsingCharset(bb, StandardCharsets.UTF_16LE, RENDER_ENUM.ALL, true);
		String s = srb.build();
		assertEquals("u\"\\uFEFFtest\"", s);
	}
}
