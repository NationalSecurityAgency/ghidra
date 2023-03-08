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

import static org.junit.Assert.assertEquals;

import java.util.List;

import java.io.*;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.NumericUtilities;

public class LEB128Test extends AbstractGTest {
	static record TestEntry(long expectedValue, byte[] bytes) {
		MemBuffer mb() {
			return new ByteMemBufferImpl(null, bytes, false /* don't matter */);
		}
	}

	private static InputStream is(int... intBytes) {
		return is(bytes(intBytes));
	}

	private static InputStream is(byte[] bytes) {
		ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
		return bais;
	}

	static TestEntry te(long expectedValue, int... intBytes) {
		return new TestEntry(expectedValue, bytes(intBytes));
	}

	/* package */ List<TestEntry> unsignedTestEntries = List.of(
		// misc
		te(0L, 0x80, 0x80, 0x80, 0x80, 0x80, 0x0), // Tests reading a zero value that is encoded in non-optimal way.
		te(1L, 0x81, 0x80, 0x80, 0x80, 0x80, 0x0), // Tests reading a 1 value that is encoded in non-optimal way.
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

	/* package */ List<TestEntry> signedTestEntries = List.of(
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
			InputStream is = is(te.bytes);
			long actualValue = LEB128.read(is, signed);
			int remainder = is.available();
			assertEquals(String.format(
				"%s[%d] failed: leb128(%s) != %d. Expected=%d / %x, actual=%d / %x",
				name, i, NumericUtilities.convertBytesToString(te.bytes), te.expectedValue,
				te.expectedValue, te.expectedValue, actualValue, actualValue), te.expectedValue,
				actualValue);
			assertEquals(String.format("%s[%d] failed: left-over bytes: %d", name, i, remainder),
				0, is.available());
		}
	}

	@Test(expected = IOException.class)
	public void testToolargeUnsigned() throws IOException {
		// Test reading a unsigned LEB128 that is just 1 bit too large for a java 64 bit long int.
		InputStream is = is(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02);

		long value = LEB128.read(is, false);
		Assert.fail(
			"Should not be able to read a LEB128 that is larger than what can fit in java 64bit long int: " +
				value);
	}

	@Test
	public void testTooLargeValueBinaryReaderStreamPosition() throws IOException {
		// Test that the BinaryReader stream is 'correctly' positioned after the LEB128 bytes after 
		// reading a LEB128 that is too large for a java 64 bit long int.

		byte[] bytes =
			bytes(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x1, 0x2);
		InputStream is = is(bytes);

		try {
			long value = LEB128.read(is, false);
			Assert.fail(
				"Should not be able to read a LEB128 that is larger than what can fit in java 64bit long int: " +
					Long.toUnsignedString(value));
		}
		catch (IOException ioe) {
			// good
		}

		Assert.assertEquals(bytes.length - 10, is.available());
	}

}
