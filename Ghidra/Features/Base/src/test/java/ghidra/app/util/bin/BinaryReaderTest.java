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
package ghidra.app.util.bin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.Test;

import ghidra.util.NumberUtil;

public class BinaryReaderTest {

	private BinaryReader br(boolean isLE, int... values) {
		byte[] bytes = new byte[values.length];
		for (int i = 0; i < values.length; i++) {
			bytes[i] = (byte) values[i];
		}
		return new BinaryReader(new ByteArrayProvider(bytes), isLE);
	}

	@Test
	public void testClone() throws Exception {
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(new byte[1024]), true);
		reader.setPointerIndex(0x100);

		BinaryReader readerClone = reader.clone(0x200);
		assertEquals(0x100, reader.getPointerIndex());
		assertEquals(0x200, readerClone.getPointerIndex());
	}

	// ------------------------------------------------------------------------------------
	// Bytes
	// ------------------------------------------------------------------------------------

	@Test
	public void testReadByte() throws IOException {
		BinaryReader br = br(true, 1, 2, 127, 255, 0);

		assertEquals(1, br.readByte(0));
		assertEquals(2, br.readByte(1));
		assertEquals(127, br.readByte(2));
		assertEquals(-1, br.readByte(3));
		assertEquals(0, br.readByte(4));
		try {
			br.readByte(5);
			fail("Should have triggered IOException");
		}
		catch (IOException ioe) {
			// good
		}
	}

	@Test
	public void testReadUnsignedByte() throws IOException {
		BinaryReader br = br(true, 1, 2, 127, 255, 0);

		assertEquals(1, br.readUnsignedByte(0));
		assertEquals(2, br.readUnsignedByte(1));
		assertEquals(127, br.readUnsignedByte(2));
		assertEquals(255, br.readUnsignedByte(3));
		assertEquals(0, br.readUnsignedByte(4));
		try {
			br.readUnsignedByte(5);
			fail("Should have triggered IOException");
		}
		catch (IOException ioe) {
			// good
		}
	}

	@Test
	public void testReadNextByte() throws IOException {
		BinaryReader br = br(true, 1, 2, 127, 255, 0);

		assertEquals(1, br.readNextByte());
		assertEquals(2, br.readNextByte());
		assertEquals(127, br.readNextByte());
		assertEquals(-1, br.readNextByte());
		assertEquals(0, br.readNextByte());
		try {
			br.readNextByte();
			fail("Should have triggered IOException");
		}
		catch (IOException ioe) {
			// good
		}
	}

	@Test
	public void testReadNextUnsignedByte() throws IOException {
		BinaryReader br = br(true, 1, 2, 127, 255, 0);

		assertEquals(1, br.readNextUnsignedByte());
		assertEquals(2, br.readNextUnsignedByte());
		assertEquals(127, br.readNextUnsignedByte());
		assertEquals(255, br.readNextUnsignedByte());
		assertEquals(0, br.readNextUnsignedByte());
		try {
			br.readNextUnsignedByte();
			fail("Should have triggered IOException");
		}
		catch (IOException ioe) {
			// good
		}
	}

	// ------------------------------------------------------------------------------------
	// Shorts
	// ------------------------------------------------------------------------------------

	@Test
	public void testReadShort() throws IOException {
		BinaryReader br = br(true, 1, 0, 0xff, 0x7f, 0xff, 0xff, 0x00, 0x80);

		assertEquals(1, br.readShort(0));
		assertEquals(Short.MAX_VALUE, br.readShort(2));
		assertEquals(-1, br.readShort(4));
		assertEquals(Short.MIN_VALUE, br.readShort(6));
		try {
			br.readShort(8);
			fail("Should have triggered IOException");
		}
		catch (IOException ioe) {
			// good
		}
	}

	@Test
	public void testReadUnsignedShort() throws IOException {
		BinaryReader br = br(true, 1, 0, 0xff, 0x7f, 0xff, 0xff, 0x00, 0x80);

		assertEquals(1, br.readUnsignedShort(0));
		assertEquals(Short.MAX_VALUE /* 0x7fff */, br.readUnsignedShort(2));
		assertEquals(NumberUtil.UNSIGNED_SHORT_MASK /* ie. UNSIGNED_SHORT_MAX, 0xffff*/,
			br.readUnsignedShort(4));
		assertEquals(Short.MAX_VALUE + 1 /* 0x8000 */, br.readUnsignedShort(6));
		try {
			br.readUnsignedShort(8);
			fail("Should have triggered IOException");
		}
		catch (IOException ioe) {
			// good
		}
	}

	@Test
	public void testReadNextShort() throws IOException {
		BinaryReader br = br(true, 1, 0, 0xff, 0x7f, 0xff, 0xff, 0x00, 0x80);

		assertEquals(1, br.readNextShort());
		assertEquals(Short.MAX_VALUE, br.readNextShort());
		assertEquals(-1, br.readNextShort());
		assertEquals(Short.MIN_VALUE, br.readNextShort());
		try {
			br.readNextShort();
			fail("Should have triggered IOException");
		}
		catch (IOException ioe) {
			// good
		}
	}

	@Test
	public void testReadNextUnsignedShort() throws IOException {
		BinaryReader br = br(true, 1, 0, 0xff, 0x7f, 0xff, 0xff, 0x00, 0x80);

		assertEquals(1, br.readNextUnsignedShort());
		assertEquals(Short.MAX_VALUE /* 0x7fff */, br.readNextUnsignedShort());
		assertEquals(NumberUtil.UNSIGNED_SHORT_MASK /* ie. UNSIGNED_SHORT_MAX, 0xffff*/,
			br.readNextUnsignedShort());
		assertEquals(Short.MAX_VALUE + 1 /* 0x8000 */, br.readNextUnsignedShort());
		try {
			br.readNextUnsignedShort();
			fail("Should have triggered IOException");
		}
		catch (IOException ioe) {
			// good
		}
	}

	// ------------------------------------------------------------------------------------
	// Ints
	// ------------------------------------------------------------------------------------

	@Test
	public void testReadInt() throws IOException {
		BinaryReader br =
			br(true, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0x80);

		assertEquals(1, br.readInt(0));
		assertEquals(Integer.MAX_VALUE, br.readInt(4));
		assertEquals(-1, br.readInt(8));
		assertEquals(Integer.MIN_VALUE, br.readInt(12));
		try {
			br.readInt(16);
			fail("Should have triggered IOException");
		}
		catch (IOException ioe) {
			// good
		}
	}

	@Test
	public void testReadUnsignedInt() throws IOException {
		BinaryReader br =
			br(true, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0x80);

		assertEquals(1, br.readUnsignedInt(0));
		assertEquals(Integer.MAX_VALUE, br.readUnsignedInt(4));
		assertEquals(NumberUtil.UNSIGNED_INT_MASK /*ie. UNSIGNED_INT_MAX, 0xff_ff_ff_ff*/,
			br.readUnsignedInt(8));
		assertEquals((long) Integer.MAX_VALUE + 1 /* 0x80_00_00_00 */, br.readUnsignedInt(12));
		try {
			br.readUnsignedInt(16);
			fail("Should have triggered IOException");
		}
		catch (IOException ioe) {
			// good
		}
	}

	@Test
	public void testReadNextInt() throws IOException {
		BinaryReader br =
			br(true, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0x80);

		assertEquals(1, br.readNextInt());
		assertEquals(Integer.MAX_VALUE, br.readNextInt());
		assertEquals(-1, br.readNextInt());
		assertEquals(Integer.MIN_VALUE, br.readNextInt());
		try {
			br.readNextInt();
			fail("Should have triggered IOException");
		}
		catch (IOException ioe) {
			// good
		}
	}

	@Test
	public void testReadNextUnsignedInt() throws IOException {
		BinaryReader br =
			br(true, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0x80);

		assertEquals(1, br.readNextUnsignedInt());
		assertEquals(Integer.MAX_VALUE, br.readNextUnsignedInt());
		assertEquals(NumberUtil.UNSIGNED_INT_MASK /*ie. UNSIGNED_INT_MAX, 0xff_ff_ff_ff*/,
			br.readNextUnsignedInt());
		assertEquals((long) Integer.MAX_VALUE + 1 /* 0x80_00_00_00 */, br.readNextUnsignedInt());
		try {
			br.readNextUnsignedInt();
			fail("Should have triggered IOException");
		}
		catch (IOException ioe) {
			// good
		}
	}

	// ------------------------------------------------------------------------------------
	// UTF-16 Unicode String
	// ------------------------------------------------------------------------------------
	@Test
	public void testReadUnicodeString_LE() throws IOException {
		BinaryReader br = br(true, 1, 1, 1, 'A', 0, 'B', 0, 'C', 0, 0, 0x80, 0);
		assertEquals("ABC\u8000", br.readUnicodeString(3, 4));
	}

	@Test
	public void testReadUnicodeString_BE() throws IOException {
		BinaryReader br = br(false, 1, 1, 1, 0, 'A', 0, 'B', 0, 'C', 0x80, 0, 0);
		assertEquals("ABC\u8000", br.readUnicodeString(3, 4));
	}

	@Test
	public void testReadTerminatedUnicodeString_LE() throws IOException {
		BinaryReader br = br(true, 1, 1, 1, 'A', 0, 'B', 0, 'C', 0, 0, 0x80, 0, 0);

		assertEquals("ABC\u8000", br.readUnicodeString(3));
	}

	@Test
	public void testReadTerminatedUnicodeString_BE() throws IOException {
		BinaryReader br = br(false, 1, 1, 1, 0, 'A', 0, 'B', 0, 'C', 0x80, 0, 0, 0);

		assertEquals("ABC\u8000", br.readUnicodeString(3));
	}

	@Test
	public void testReadNextUnicodeString_LE() throws IOException {
		BinaryReader br =
			br(true, 1, 1, 1, 'A', 0, 'B', 0, 'C', 0, 0, 0x80, 0, 0, /* magic flag value */ 42);
		br.setPointerIndex(3);
		assertEquals("ABC\u8000", br.readNextUnicodeString());
		assertEquals(42, br.readNextUnsignedByte());
	}

	@Test
	public void testReadNextUnicodeString_BE() throws IOException {
		BinaryReader br =
			br(false, 1, 1, 1, 0, 'A', 0, 'B', 0, 'C', 0x80, 0, 0, 0, /* magic flag value */ 42);
		br.setPointerIndex(3);
		assertEquals("ABC\u8000", br.readNextUnicodeString());
		assertEquals(42, br.readNextUnsignedByte());
	}

}
