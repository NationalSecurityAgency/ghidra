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
package ghidra.app.util.bin.format.dwarf4;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

import java.io.IOException;

import org.junit.Assert;
import org.junit.Test;

public class LEB128Test {

	private static final boolean BR_IS_LITTLE_ENDIAN = true;

	private BinaryReader br(byte... bytes) {
		return new BinaryReader(new ByteArrayProvider(bytes), BR_IS_LITTLE_ENDIAN);
	}

	/**
	 * Test reading the largest unsigned LEB128 int that we can handle (64 used bits).
	 * <p>
	 *  
	 * @throws IOException
	 */
	@Test
	public void testMax64bitUnsigned() throws IOException {
		byte[] bytes = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x01 };

		long value = LEB128.decode(bytes, false);

		// -1 signed long == MAX unsigned 
		Assert.assertEquals(-1, value);
	}

	/**
	 * Test reading a number that is larger than 32 bits to ensure that all the shifting
	 * done in the LEB128 reader doesn't have a 32bit fault.
	 * @throws IOException
	 */
	@Test
	public void test36bitUnsigned() throws IOException {
		byte[] bytes = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0x01 };

		long value = LEB128.decode(bytes, false);
		Assert.assertEquals(0xfffffffffL, value);
	}

	@Test
	public void testSignedNeg2() throws IOException {
		byte[] bytes = new byte[] { (byte) 0x7e };

		long value = LEB128.decode(bytes, true);
		Assert.assertEquals(-2, value);
	}

	@Test
	public void testSignedNeg127() throws IOException {
		byte[] bytes = new byte[] { (byte) 0x81, (byte) 0x7f };

		long value = LEB128.decode(bytes, true);
		Assert.assertEquals(-127, value);
	}

	@Test
	public void testSignedNeg128() throws IOException {
		byte[] bytes = new byte[] { (byte) 0x80, (byte) 0x7f };

		long value = LEB128.decode(bytes, true);
		Assert.assertEquals(-128, value);
	}

	@Test
	public void testSignedNeg129() throws IOException {
		byte[] bytes = new byte[] { (byte) 0xff, (byte) 0x7e };

		long value = LEB128.decode(bytes, true);
		Assert.assertEquals(-129, value);
	}

	@Test
	public void testSigned129() throws IOException {
		byte[] bytes = new byte[] { (byte) 0x81, (byte) 0x1 };

		long value = LEB128.decode(bytes, true);
		Assert.assertEquals(129, value);
	}

	/**
	 * Tests reading an zero value that is encoded in non-optimal way.
	 * @throws IOException
	 */
	@Test
	public void testAltZeroEncoded() throws IOException {
		byte[] bytes = new byte[] { (byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80,
			(byte) 0x0 };

		long value = LEB128.decode(bytes, false);
		Assert.assertEquals(0, value);
	}

	/**
	 * Test a 36bit signed negative value.
	 * 
	 * @throws IOException
	 */
	@Test
	public void test36bitSignedNeg() throws IOException {
		byte[] bytes = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0x41 };

		long value = LEB128.decode(bytes, true);
		Assert.assertEquals(-2130303778817L, value);
	}

	/**
	 * Test reading a unsigned LEB128 that is just 1 bit too large for a java 64 bit long int. 
	 * @throws IOException
	 */
	@Test
	public void testToolargeUnsigned() throws IOException {
		byte[] bytes = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x02 };

		try {
			long value = LEB128.decode(bytes, false);
			Assert.fail(
				"Should not be able to read a LEB128 that is larger than what can fit in java 64bit long int: " +
					value);
		}
		catch (IOException ioe) {
			// good
		}
	}

	/**
	 * Test that the BinaryReader stream is correctly positioned after the LEB128 bytes after 
	 * reading a LEB128 that is too large for a java 64 bit long int.
	 * 
	 * @throws IOException
	 */
	@Test
	public void testToolargeBinaryReaderStreamPosition() throws IOException {
		BinaryReader br = br((byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0x02, (byte) 0x1, (byte) 0x2);

		try {
			long value = LEB128.decode(br, false);
			Assert.fail(
				"Should not be able to read a LEB128 that is larger than what can fit in java 64bit long int: " +
					Long.toUnsignedString(value));
		}
		catch (IOException ioe) {
			// good
		}

		Assert.assertEquals(1, br.readNextByte() & 0xFF);
		Assert.assertEquals(2, br.readNextByte() & 0xFF);
	}

	/**
	 * Test uint32 max
	 * 
	 * @throws IOException
	 */
	@Test
	public void testUint32Max() throws IOException {
		int value =
			LEB128.decode32u(br((byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x07));
		Assert.assertEquals(Integer.MAX_VALUE, value);
	}

	/**
	 * Test uint32 max overflow with 0xff_ff_ff_ff
	 * 
	 * @throws IOException
	 */
	@Test
	public void testUint32Overflow() throws IOException {
		try {
			int value = LEB128.decode32u(
				br((byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x0f));
			Assert.fail(
				"Should not be able to read a LEB128 that is larger than what can fit in java 32 bit int: " +
					Integer.toUnsignedString(value));
		}
		catch (IOException ioe) {
			// good
		}
	}
}
