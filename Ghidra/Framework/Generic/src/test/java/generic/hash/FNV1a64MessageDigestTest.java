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
package generic.hash;

import static org.junit.Assert.assertEquals;

import java.util.Random;

import org.junit.Before;
import org.junit.Test;

import ghidra.util.task.TaskMonitorAdapter;

public class FNV1a64MessageDigestTest {

	private MessageDigest digest;

	@Before
	public void setUp() throws Exception {
		digest = new FNV1a64MessageDigest();
	}

	@Test
	public void testBasicValues() throws Exception {
		byte[] input = bytearray(0xd5, 0x6b, 0xb9, 0x53, 0x42, 0x87, 0x08, 0x36);
		byte[] target = bytearray(0, 0, 0, 0, 0, 0, 0, 0);
		digest.update(input, TaskMonitorAdapter.DUMMY_MONITOR);
		byte[] actual = digest.digest();
		assertArrayEquals(target, actual);
	}

	private static final byte MARKER = 0x42;

	private static String formatIndex(int ii, int beforeLength, int requestLength,
			int actualRequestLength, int afterLength) {
		return ii + " (" + beforeLength + "," + requestLength + "[" + actualRequestLength + "]," +
			afterLength + ")";
	}

	@Test
	public void testLongEquivalence() throws Exception {
		Random random = new Random();
		for (int ii = 0; ii < 10; ++ii) {
			byte[] input = new byte[20];
			random.nextBytes(input);
			digest.update(input, TaskMonitorAdapter.DUMMY_MONITOR);
			byte[] bytes = digest.digest();
			digest.update(input, TaskMonitorAdapter.DUMMY_MONITOR);
			long asLong = digest.digestLong();

			long acc = 0;
			for (byte b : bytes) {
				acc <<= 8;
				acc |= b & 0xff;
			}
			assertEquals(asLong, acc);
		}
	}

	@Test
	public void testLongerRequests() throws Exception {
		byte[] input = bytearray('F', 'o', 'o', 'b', 'a', 'r');
		digest.update(input, TaskMonitorAdapter.DUMMY_MONITOR);
		byte[] reference = digest.digest();

		for (int beforeLength = 0; beforeLength < digest.getDigestLength(); ++beforeLength) {
			for (int requestLength = 0; requestLength < digest.getDigestLength() *
				2; ++requestLength) {
				for (int afterLength = 0; afterLength < digest.getDigestLength(); ++afterLength) {
					final int actualRequestLength = (requestLength < digest.getDigestLength()
							? requestLength : digest.getDigestLength());
					byte[] output = new byte[beforeLength + actualRequestLength + afterLength];
					for (int ii = 0; ii < output.length; ++ii) {
						output[ii] = MARKER;
					}
					digest.update(input, TaskMonitorAdapter.DUMMY_MONITOR);
					digest.digest(output, beforeLength, requestLength);
					for (int ii = 0; ii < beforeLength; ++ii) {
						assertEquals(
							"failed before, at index " + formatIndex(ii, beforeLength,
								requestLength, actualRequestLength, afterLength),
							MARKER, output[ii]);
					}
					for (int ii = beforeLength, jj = 0; ii < beforeLength +
						actualRequestLength; ++ii, ++jj) {
						assertEquals(
							"failed digest (middle), at index " + formatIndex(ii, beforeLength,
								requestLength, actualRequestLength, afterLength),
							reference[jj], output[ii]);
					}
					for (int ii = beforeLength + actualRequestLength; ii < output.length; ++ii) {
						assertEquals("failed after, at index " + formatIndex(ii, beforeLength,
							requestLength, actualRequestLength, afterLength), MARKER, output[ii]);
					}
				}
			}
		}
	}

	private static void assertArrayEquals(byte[] expected, byte[] actual) {
		if (expected.length != actual.length) {
			throw new AssertionError(
				"actual array " + (expected.length > actual.length ? "shorter" : "longer") + " (" +
					actual.length + ") than expected (" + expected.length + ")");
		}
		for (int ii = 0; ii < expected.length; ++ii) {
			if (expected[ii] != actual[ii]) {
				throw new AssertionError(
					"expected " + expected[ii] + " at index " + ii + ", actual was " + actual[ii]);
			}
		}
	}

	private static byte[] bytearray(int... iarray) {
		byte[] result = new byte[iarray.length];
		for (int ii = 0; ii < iarray.length; ++ii) {
			result[ii] = (byte) (iarray[ii] & 0xff);
		}
		return result;
	}
}
