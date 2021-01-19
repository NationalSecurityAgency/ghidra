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

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.util.NumericUtilities;

public class LEB128Test {

	private static final boolean BR_IS_LITTLE_ENDIAN = true;

	private BinaryReader br(int... intBytes) {
		byte[] bytes = new byte[intBytes.length];
		for (int i = 0; i < intBytes.length; i++) {
			bytes[i] = (byte) intBytes[i];
		}
		return new BinaryReader(new ByteArrayProvider(bytes), BR_IS_LITTLE_ENDIAN);
	}

	static class TestEntry {
		long expectedValue;
		byte[] bytes;

		TestEntry(long expectedValue, byte[] bytes) {
			this.expectedValue = expectedValue;
			this.bytes = bytes;
		}
	}

	private TestEntry te(long expectedValue, int... intBytes) {
		byte[] bytes = new byte[intBytes.length];
		for (int i = 0; i < intBytes.length; i++) {
			bytes[i] = (byte) intBytes[i];
		}
		return new TestEntry(expectedValue, bytes);
	}

	private List<TestEntry> unsignedTestEntries = List.of(
		// misc
		te(0L, 0x80, 0x80, 0x80, 0x80, 0x80, 0x0), // Tests reading a zero value that is encoded in non-optimal way.
		te(-1L, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01),  // -1 == MAX unsigned long
		te(0xf_ffff_ffffL, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01),	// more than 32 bits to test shifting > 32bits

		// 1 byte
		te(1L, 0x01),
		te(63L, 0x3f),
		te(64L, 0x40),

		// 1 byte to 2 byte transition
		te(125L, 0x7d),
		te(126L, 0x7e),
		te(127L, 0x7f),
		te(128L, 0x80, 0x01),
		te(129L, 0x81, 0x01),
		te(130L, 0x82, 0x01),
		te(131L, 0x83, 0x01),

		te(254L, 0xfe, 0x01),
		te(255L, 0xff, 0x01),
		te(256L, 0x80, 0x02),
		te(257L, 0x81, 0x02),

		// 2 byte to 3 byte transition
		te(16382L, 0xfe, 0x7f),
		te(16383L, 0xff, 0x7f),
		te(16384L, 0x80, 0x80, 0x01),
		te(16385L, 0x81, 0x80, 0x01),

		// 3 byte to 4 byte transition
		te(2097151L, 0xff, 0xff, 0x7f),
		te(2097152L, 0x80, 0x80, 0x80, 0x01),
		te(2097153L, 0x81, 0x80, 0x80, 0x01),

		// 4 byte to 5 byte transition
		te(268435455L, 0xff, 0xff, 0xff, 0x7f),
		te(268435456L, 0x80, 0x80, 0x80, 0x80, 0x01),
		te(268435457L, 0x81, 0x80, 0x80, 0x80, 0x01),

		// 5 byte to 6 byte transition
		te(34359738367L, 0xff, 0xff, 0xff, 0xff, 0x7f),
		te(34359738368L, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01),
		te(34359738369L, 0x81, 0x80, 0x80, 0x80, 0x80, 0x01)
	//
	);

	private List<TestEntry> signedTestEntries = List.of(
		// misc
		te(-2130303778817L, 0xff, 0xff, 0xff, 0xff, 0xff, 0x41),

		// 1 byte positive stuff
		te(0L, 0x00),
		te(1L, 0x01),

		// 1 byte to 2 byte transition (positive)
		te(63L, 0x3f),
		te(64L, 0xc0, 0x00),
		te(65L, 0xc1, 0x00),
		te(66L, 0xc2, 0x00),

		te(126L, 0xfe, 0x00),
		te(127L, 0xff, 0x00),
		te(128L, 0x80, 0x01),
		te(129L, 0x81, 0x01),

		te(254L, 0xfe, 0x01),
		te(255L, 0xff, 0x01),
		te(256L, 0x80, 0x02),
		te(257L, 0x81, 0x02),

		// 2 byte to 3 byte transition
		te(8190L, 0xfe, 0x3f),
		te(8191L, 0xff, 0x3f),
		te(8192L, 0x80, 0xc0, 0x00),
		te(8193L, 0x81, 0xc0, 0x00),

		// 1 byte negative stuff
		te(-1L, 0x7f),
		te(-2L, 0x7e),
		te(-3L, 0x7d),
		te(-4L, 0x7c),
		te(-5L, 0x7b),
		te(-6L, 0x7a),

		// 1 byte to 2 byte transition (negative)
		te(-64L, 0x40),
		te(-65L, 0xbf, 0x7f),

		te(-127, 0x81, 0x7f),
		te(-128, 0x80, 0x7f),
		te(-129, 0xff, 0x7e),

		// 2 byte to 3 byte transition (negative)
		te(-8191L, 0x81, 0x40),
		te(-8192L, 0x80, 0x40),
		te(-8193L, 0xff, 0xbf, 0x7f),
		te(-8194L, 0xfe, 0xbf, 0x7f)

	);

	@Test
	public void testUnsignedTestEntries() throws IOException {
		testTestEntries(unsignedTestEntries, false, "Unsigned TestEntry");
	}

	@Test
	public void testSignedTestEntries() throws IOException {
		testTestEntries(signedTestEntries, true, "Signed TestEntry");
	}

	public void testTestEntries(List<TestEntry> testEntries, boolean signed, String name)
			throws IOException {
		for (int i = 0; i < testEntries.size(); i++) {
			TestEntry te = testEntries.get(i);
			BinaryReader br =
				new BinaryReader(new ByteArrayProvider(te.bytes), BR_IS_LITTLE_ENDIAN);
			long actualValue = LEB128.readAsLong(br, signed);
			assertEquals(String.format(
				"%s[%d] failed: leb128(%s) != %d. Expected=%d / %x, actual=%d / %x",
				name, i, NumericUtilities.convertBytesToString(te.bytes), te.expectedValue,
				te.expectedValue, te.expectedValue, actualValue, actualValue), te.expectedValue,
				actualValue);
			assertEquals(String.format("%s[%d] failed: left-over bytes: %d", name, i,
				te.bytes.length - br.getPointerIndex()), te.bytes.length, br.getPointerIndex());
		}
	}

	@Test(expected = IOException.class)
	public void testToolargeUnsigned() throws IOException {
		// Test reading a unsigned LEB128 that is just 1 bit too large for a java 64 bit long int.

		BinaryReader br = br(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02);

		long value = LEB128.readAsLong(br, false);
		Assert.fail(
			"Should not be able to read a LEB128 that is larger than what can fit in java 64bit long int: " +
				value);
	}

	@Test
	public void testTooLargeValueBinaryReaderStreamPosition() {
		// Test that the BinaryReader stream is 'correctly' positioned after the LEB128 bytes after 
		// reading a LEB128 that is too large for a java 64 bit long int.

		BinaryReader br =
			br(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x1, 0x2);

		try {
			long value = LEB128.readAsLong(br, false);
			Assert.fail(
				"Should not be able to read a LEB128 that is larger than what can fit in java 64bit long int: " +
					Long.toUnsignedString(value));
		}
		catch (IOException ioe) {
			// good
		}

		Assert.assertEquals(10, br.getPointerIndex());
	}

	@Test
	public void testUint32Max() throws IOException {
		int value = LEB128.readAsUInt32(br(0xff, 0xff, 0xff, 0xff, 0x07));
		Assert.assertEquals(Integer.MAX_VALUE, value);
	}

	@Test(expected = IOException.class)
	public void testUint32Overflow() throws IOException {

		// Test uint32 max overflow with 0xff_ff_ff_ff

		int value = LEB128.readAsUInt32(br(0xff, 0xff, 0xff, 0xff, 0x0f));
		Assert.fail(
			"Should not be able to read a LEB128 that is larger than what can fit in java 32 bit int: " +
				Integer.toUnsignedString(value));
	}
}
