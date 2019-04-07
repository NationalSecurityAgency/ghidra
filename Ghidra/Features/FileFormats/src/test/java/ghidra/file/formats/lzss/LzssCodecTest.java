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
package ghidra.file.formats.lzss;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.*;

import org.junit.Test;

public class LzssCodecTest {
	/*
	 * Example taken from Wikipedia's LZSS article. Accessed 15 Feb 2019.
	 * 
	 * They, in turn, took it from Dr. Seuss's Green Eggs and Ham, as it
	 * contains many repeated words, making for great compression fodder.
	 */
	public static final String TEST_TEXT = "" + //
		"I am Sam\n" + //
		"\n" + //
		"Sam I am\n" + //
		"\n" + //
		"That Sam-I-am!\n" + //
		"That Sam-I-am!\n" + //
		"I do not like\n" + //
		"that Sam-I-am!\n" + //
		"\n" + //
		"Do you like green eggs and ham?\n" + //
		"\n" + //
		"I do not like them, Sam-I-am.\n" + //
		"I do not like green eggs and ham.";

	public static final byte[] TEST_COMPRESSED = new byte[] { //
		(byte) 0xff, (byte) 0x49, (byte) 0x20, (byte) 0x61, //
		(byte) 0x6d, (byte) 0x20, (byte) 0x53, (byte) 0x61, //
		(byte) 0x6d, (byte) 0xf3, (byte) 0x0a, (byte) 0x0a, //
		(byte) 0xf3, (byte) 0xf0, (byte) 0xed, (byte) 0xf2, //
		(byte) 0x0a, (byte) 0x0a, (byte) 0x54, (byte) 0x68, //
		(byte) 0xfb, (byte) 0x61, (byte) 0x74, (byte) 0xf2, //
		(byte) 0xf1, (byte) 0x2d, (byte) 0x49, (byte) 0x2d, //
		(byte) 0x61, (byte) 0x6d, (byte) 0xfd, (byte) 0x21, //
		(byte) 0x01, (byte) 0x0d, (byte) 0x49, (byte) 0x20, //
		(byte) 0x64, (byte) 0x6f, (byte) 0x20, (byte) 0x6e, //
		(byte) 0xff, (byte) 0x6f, (byte) 0x74, (byte) 0x20, //
		(byte) 0x6c, (byte) 0x69, (byte) 0x6b, (byte) 0x65, //
		(byte) 0x0a, (byte) 0xfd, (byte) 0x74, (byte) 0x03, //
		(byte) 0x0b, (byte) 0x0a, (byte) 0x44, (byte) 0x6f, //
		(byte) 0x20, (byte) 0x79, (byte) 0x6f, (byte) 0xfd, //
		(byte) 0x75, (byte) 0x28, (byte) 0x02, (byte) 0x20, //
		(byte) 0x67, (byte) 0x72, (byte) 0x65, (byte) 0x65, //
		(byte) 0x6e, (byte) 0xff, (byte) 0x20, (byte) 0x65, //
		(byte) 0x67, (byte) 0x67, (byte) 0x73, (byte) 0x20, //
		(byte) 0x61, (byte) 0x6e, (byte) 0x7f, (byte) 0x64, //
		(byte) 0x20, (byte) 0x68, (byte) 0x61, (byte) 0x6d, //
		(byte) 0x3f, (byte) 0x0a, (byte) 0x1f, (byte) 0x0b, //
		(byte) 0xbf, (byte) 0x20, (byte) 0x74, (byte) 0x68, //
		(byte) 0x65, (byte) 0x6d, (byte) 0x2c, (byte) 0x06, //
		(byte) 0x06, (byte) 0x2e, (byte) 0x04, (byte) 0x5e, //
		(byte) 0x0c, (byte) 0x4a, (byte) 0x0f, (byte) 0x2e, //
	};

	@Test
	public void testCompress() throws Exception {
		ByteArrayOutputStream dst = new ByteArrayOutputStream();
		InputStream src = new ByteArrayInputStream(TEST_TEXT.getBytes());
		LzssCodec.compress(dst, src);
		byte[] out = dst.toByteArray();

		assertArrayEquals(TEST_COMPRESSED, out);
	}

	@Test
	public void testDecompress() throws Exception {
		ByteArrayOutputStream dst = new ByteArrayOutputStream();
		InputStream src = new ByteArrayInputStream(TEST_COMPRESSED);
		LzssCodec.decompress(dst, src);
		String out = new String(dst.toByteArray());

		assertEquals(TEST_TEXT, out);
	}
}
