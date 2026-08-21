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
package ghidra.features.base.memsearch.format;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;

import org.junit.Test;

public class StringSearchFormatTest extends AbstractSearchFormatTest {

	public StringSearchFormatTest() {
		super(SearchFormat.STRING);
		settings = settings.withCaseSensitive(true);
		settings = settings.withUseEscapeSequence(false);
	}

	@Test
	public void testCaseSensitive() {
		matcher = parse("aBc12");

		assertBytes(0x61, 0x42, 0x63, 0x31, 0x32);
		assertMask(0xff, 0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testCaseInSensitriveUTF8() {
		settings = settings.withCaseSensitive(false);
		matcher = parse("aBc12");

		assertBytes(0x41, 0x42, 0x43, 0x31, 0x32);
		assertMask(0xdf, 0xdf, 0xdf, 0xff, 0xff);
	}

	@Test
	public void testCaseSensitiveUTF8() {
		settings = settings.withStringCharset(StandardCharsets.UTF_8);
		matcher = parse("aBc12");

		assertBytes(0x61, 0x42, 0x63, 0x31, 0x32);
		assertMask(0xff, 0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testCaseInSensitrive() {
		settings = settings.withCaseSensitive(false);
		matcher = parse("aBc12");

		assertBytes(0x41, 0x42, 0x43, 0x31, 0x32);
		assertMask(0xdf, 0xdf, 0xdf, 0xff, 0xff);
	}

	@Test
	public void testEscapeSequence() {
		settings = settings.withUseEscapeSequence(false);
		matcher = parse("a\\n");
		assertBytes(0x61, 0x5c, 0x6e);

		settings = settings.withUseEscapeSequence(true);
		matcher = parse("a\\n");
		assertBytes(0x61, 0x0a);

	}

	@Test
	public void testUTF16CaseSensitiveLittleEndian() {
		settings = settings.withBigEndian(false);
		settings = settings.withStringCharset(StandardCharsets.UTF_16);
		matcher = parse("aBc12");

		assertBytes(0x61, 0x0, 0x42, 0x0, 0x63, 0x0, 0x31, 0x0, 0x32, 0x0);
		assertMask(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testUTF16CaseSensitiveBigEndian() {
		settings = settings.withBigEndian(true);
		settings = settings.withStringCharset(StandardCharsets.UTF_16);
		matcher = parse("aBc12");

		assertBytes(0x00, 0x61, 0x0, 0x42, 0x0, 0x63, 0x0, 0x31, 0x0, 0x32);
		assertMask(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testUTF16CaseInSensitiveLittleEndian() {
		settings = settings.withCaseSensitive(false);
		settings = settings.withBigEndian(false);
		settings = settings.withStringCharset(StandardCharsets.UTF_16);
		matcher = parse("aBc12");

		assertBytes(0x41, 0x0, 0x42, 0x0, 0x43, 0x0, 0x31, 0x0, 0x32, 0x0);
		assertMask(0xdf, 0xff, 0xdf, 0xff, 0xdf, 0xff, 0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testUTF16CaseInSensitiveBigEndian() {
		settings = settings.withCaseSensitive(false);
		settings = settings.withBigEndian(true);
		settings = settings.withStringCharset(StandardCharsets.UTF_16);
		matcher = parse("aBc12");

		assertBytes(0x00, 0x41, 0x0, 0x42, 0x0, 0x43, 0x0, 0x31, 0x0, 0x32);
		assertMask(0xff, 0xdf, 0xff, 0xdf, 0xff, 0xdf, 0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testConvertTextFromBinary() {
		assertEquals("10001000 11111111", convertText(binarySettings, "10001000 11111111"));
		assertEquals("1 0", convertText(binarySettings, "1 0"));
	}

	@Test
	public void testConvertTextFromHex() {
		assertEquals("56 12", convertText(hexSettings, "56 12"));
		assertEquals("1 0", convertText(hexSettings, "1 0"));
	}

	@Test
	public void testConvertTextFromInts() {
		assertEquals("0 22 -1 -14", convertText(int1Settings, "0 22 -1 -14"));
		assertEquals("0 22 -1 -14", convertText(int2Settings, "0 22 -1 -14"));
		assertEquals("0 22 -1 -14", convertText(int8Settings, "0 22 -1 -14"));

		assertEquals("20000000", convertText(int4Settings, "20000000"));
		assertEquals("2000000000000", convertText(int8Settings, "2000000000000"));

	}

	@Test
	public void testConvertTextFromUnsignedInts() {
		assertEquals("0 22 255", convertText(uint1Settings, "0 22 255"));
		assertEquals("0 22 65535", convertText(uint2Settings, "0 22 65535"));
		assertEquals("22 4294967295", convertText(uint4Settings, "22 4294967295"));
		assertEquals("22", convertText(uint8Settings, "22"));
		assertEquals("18446744073709551615",
			convertText(uint8Settings, "18446744073709551615"));
	}

	@Test
	public void testConvertTextFromDoubles() {
		assertEquals("1.234", convertText(doubleSettings, "1.234"));
	}

	protected void assertStringBytes(String string) {
		byte[] bytes = matcher.getBytes();
		byte[] expectedBytes = string.getBytes();
		assertArrayEquals(expectedBytes, bytes);
	}

}
