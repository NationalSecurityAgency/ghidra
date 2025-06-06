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
package ghidra.app.util.bin.format.dwarf;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

/**
 * Test reading DWARF string table
 */
public class StringTableTest extends AbstractGenericTest {

	private BinaryReader br(byte... bytes) {
		return new BinaryReader(new ByteArrayProvider(bytes), true);
	}


	@Test
	public void testStr() throws IOException {
		// @formatter:off
		BinaryReader br = br(
			/* str1 */ (byte) 'a', (byte) 'b', (byte) 0, 
			/* str2 */ (byte) 'c', (byte) 0,
			/* str3 */ (byte) 'x', (byte) 'y', (byte) '\n', (byte) 0
		);
		// @formatter:on
		StringTable st = new StringTable(br);

		assertEquals("ab", st.getStringAtOffset(0));
		assertEquals("c", st.getStringAtOffset(3));

		// test string with non-printable character
		assertEquals("xy\n", st.getStringAtOffset(5));
	}

	@Test
	public void testOffcutStr() throws IOException {
		// @formatter:off
		BinaryReader br = br(
			/* str1 */ (byte) 'a', (byte) 'b', (byte) 0, 
			/* str2 */ (byte) 'c', (byte) 0,
			/* str3 */ (byte) 'x', (byte) 'y', (byte) '\n', (byte) 0
		);
		// @formatter:on
		StringTable st = new StringTable(br);

		assertEquals("ab", st.getStringAtOffset(0));
		assertEquals("b", st.getStringAtOffset(1));
		assertEquals("c", st.getStringAtOffset(3));
		assertEquals("", st.getStringAtOffset(4));
	}

	@Test
	public void testTrailingOffcutStr() {
		// @formatter:off
		BinaryReader br = br(
			/* str1 */ (byte) 'a', (byte) 'b', (byte) 0, 
			/* str2 */ (byte) 'c', (byte) 0,
			/* str3 */ (byte) 'x', (byte) 'y', (byte) '\n', (byte) 0
		);
		// @formatter:on
		StringTable st = new StringTable(br);

		try {
			st.getStringAtOffset(9);
			fail("Should not get here");
		}
		catch (IOException ioe) {
			// good
		}
	}

	@Test
	public void testNegOffset() {
		// @formatter:off
		BinaryReader br = br(
			/* str1 */ (byte) 'a', (byte) 'b', (byte) 0, 
			/* str2 */ (byte) 'c', (byte) 0,
			/* str3 */ (byte) 'x', (byte) 'y', (byte) '\n', (byte) 0
		);
		// @formatter:on
		StringTable st = new StringTable(br);

		try {
			st.getStringAtOffset(-2);
			fail("Should not get here");
		}
		catch (IOException ioe) {
			// good
		}
	}

	@Test
	public void testEmptyStrTable() {
		BinaryReader br = br();
		StringTable st = new StringTable(br);

		try {
			st.getStringAtOffset(0);
			fail("Should not get here");
		}
		catch (IOException ioe) {
			// good
		}
	}
}
