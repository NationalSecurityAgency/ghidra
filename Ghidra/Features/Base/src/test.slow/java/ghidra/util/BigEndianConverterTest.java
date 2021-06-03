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
package ghidra.util;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.Arrays;

import org.junit.*;

import ghidra.test.AbstractGhidraHeadedIntegrationTest;

/**
 * 
 *
 * To change this generated comment edit the template variable "typecomment":
 * Window>Preferences>Java>Templates.
 * To enable and disable the creation of type comments go to
 * Window>Preferences>Java>Code Generation.
 */
public class BigEndianConverterTest extends AbstractGhidraHeadedIntegrationTest {
	private byte[] b;
	private DataConverter dc = BigEndianDataConverter.INSTANCE;

	/**
	 * Constructor for BigEndianConverterTest.
	 * @param arg0
	 */
	public BigEndianConverterTest() {
		super();
	}

	@Before
	public void setUp() {
		b = new byte[12];
		for (int i = 0; i < b.length; i++) {
			b[i] = (byte) i;
		}
	}

	@Test
	public void testGet() {
		assertEquals(0x0001, dc.getShort(b));
		assertEquals(0x0102, dc.getShort(b, 1));
		assertEquals(0x0203, dc.getShort(b, 2));

		assertEquals(0x00010203, dc.getInt(b));
		assertEquals(0x01020304, dc.getInt(b, 1));
		assertEquals(0x04050607, dc.getInt(b, 4));

		assertEquals(0x0001020304050607L, dc.getLong(b));
		assertEquals(0x0102030405060708L, dc.getLong(b, 1));
		assertEquals(0x0405060708090a0bL, dc.getLong(b, 4));

		assertEquals(0x0001L, dc.getValue(b, 2));
		assertEquals(0x000102L, dc.getValue(b, 3));
		assertEquals(0x0001020304050607L, dc.getValue(b, 8));

		assertEquals(0x0001L, dc.getSignedValue(b, 2));
		assertEquals(0x000102L, dc.getSignedValue(b, 3));
		assertEquals(0x0001020304050607L, dc.getSignedValue(b, 8));

		assertEquals(0x0203L, dc.getValue(b, 2, 2));
		assertEquals(0x020304L, dc.getValue(b, 2, 3));
		assertEquals(0x0203040506070809L, dc.getValue(b, 2, 8));

		assertEquals(0x0203, dc.getBigInteger(b, 2, 2, true).shortValue());
		assertEquals(0x04050607, dc.getBigInteger(b, 4, 4, true).intValue());
		assertEquals(0x0405060708090a0bL, dc.getBigInteger(b, 4, 8, true).longValue());

		BigInteger bint = dc.getBigInteger(bytes(0x01, 0x02, 0xff, 0x03), 2, 2, true);
		assertEquals((short) 0xff03, bint.shortValue());// -253
		assertEquals(0xffffff03, bint.intValue());

		bint = dc.getBigInteger(bytes(0x01, 0x02, 0xff, 0x03), 2, 2, false);
		assertEquals((short) 0xff03, bint.shortValue());
		assertEquals(0x0000ff03, bint.intValue());
	}

	@Test
	public void testGetSignedValues() {
		assertEquals(Integer.MIN_VALUE, dc.getSignedValue(bytes(0x80, 00, 00, 00), 4));
		assertEquals(-0x800000L, dc.getSignedValue(bytes(0x80, 00, 00, 00), 3));

		assertEquals(-256, dc.getSignedValue(bytes(0xFF, 00, 00, 00), 2));
	}

	@Test
	public void testPut() {
		byte[] b2 = new byte[12];

		Arrays.fill(b2, (byte) -1);
		dc.getBytes((short) 0x0001, b2);
		testArray(b, b2, 0, 2);

		Arrays.fill(b2, (byte) -1);
		dc.getBytes((short) 0x0102, b2, 1);
		testArray(b, b2, 1, 2);

		Arrays.fill(b2, (byte) -1);
		dc.getBytes(0x00010203, b2);
		testArray(b, b2, 0, 4);

		Arrays.fill(b2, (byte) -1);
		dc.getBytes(0x03040506, b2, 3);
		testArray(b, b2, 3, 4);

		Arrays.fill(b2, (byte) -1);
		dc.getBytes(0x0001020304050607L, b2);
		testArray(b, b2, 0, 8);

		Arrays.fill(b2, (byte) -1);
		dc.getBytes(0x030405060708090aL, b2, 3);
		testArray(b, b2, 3, 8);

		Arrays.fill(b2, (byte) -1);
		dc.getBytes(0x0102030405L, 3, b2, 3);
		testArray(b, b2, 3, 3);

		Arrays.fill(b2, (byte) -1);
		dc.getBytes(0x0102030405L, 5, b2, 1);
		testArray(b, b2, 1, 5);

		Arrays.fill(b2, (byte) -1);
		dc.getBytes(BigInteger.valueOf(0x0102030405L), 5, b2, 1);
		testArray(b, b2, 1, 5);

	}

	private void testArray(byte[] b1, byte[] b2, int off, int len) {
		for (int i = 0; i < len; i++) {
			if (b1[off + i] != b2[off + i]) {
				Assert.fail("bytes at " + (off + i) + " not equal: [" + b1[off + i] + "] [" +
					b2[off + i] + "]");
			}
		}
		for (int i = 0; i < off; i++) {
			if (b2[i] != -1) {
				Assert.fail("bytes at " + (i) + " should not have been modified, value is 0x" +
					Integer.toHexString(b2[i]));
			}
		}
		for (int i = off + len; i < b2.length; i++) {
			if (b2[i] != -1) {
				Assert.fail("bytes at " + (i) + " should not have been modified, value is 0x" +
					Integer.toHexString(b2[i]));
			}
		}
	}
}
