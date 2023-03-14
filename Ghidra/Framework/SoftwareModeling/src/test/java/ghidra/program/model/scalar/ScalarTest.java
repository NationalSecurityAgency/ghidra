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
package ghidra.program.model.scalar;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.NumericUtilities;

public class ScalarTest extends AbstractGenericTest {

	@Test
	public void testScalar0bits() {
		// test special allowance for 0-bitlength scalars that have a 0 value
		assertEquals(0, new Scalar(0, 0).getUnsignedValue());
		assertEquals(0, new Scalar(0, 0).getSignedValue());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testScalar0bitsFailure() {
		// test special allowance for 0-bitlength scalars that don't have a 0 value
		new Scalar(0, 1 /* any non-zero intial value */);
		fail("Scalar ctor should fail when asked to create a 0 bitLength scalar that isn't 0 value");
	}

	@Test
	public void testScalar64() {
		Scalar s = null;

		s = new Scalar(64, -1, true);
		Assert.assertEquals("0xffffffffffffffff", s.toString(16, true, false, "0x", ""));
		Assert.assertEquals("-0x1", s.toString(16, false, true, "0x", ""));
		Assert.assertEquals("-1", s.toString(10, true, false, "", ""));
		Assert.assertEquals("-0x1", s.toString());
		Assert.assertEquals(-1, s.getSignedValue());
		Assert.assertEquals(-1, s.getUnsignedValue());

		s = new Scalar(64, Long.MIN_VALUE, true);
		Assert.assertEquals("0x8000000000000000", s.toString(16, true, false, "0x", ""));
		Assert.assertEquals("-0x8000000000000000", s.toString(16, false, true, "0x", ""));
		Assert.assertEquals("-9223372036854775808", s.toString(10, true, false, "", ""));
		Assert.assertEquals("-0x8000000000000000", s.toString());
		Assert.assertEquals(Long.MIN_VALUE, s.getSignedValue());
		Assert.assertEquals(Long.MIN_VALUE, s.getUnsignedValue());

		s = new Scalar(64, Long.MAX_VALUE, true);
		Assert.assertEquals("0x7fffffffffffffff", s.toString(16, true, false, "0x", ""));
		Assert.assertEquals("0x7fffffffffffffff", s.toString(16, false, true, "0x", ""));
		Assert.assertEquals("9223372036854775807", s.toString(10, true, false, "", ""));
		Assert.assertEquals("0x7fffffffffffffff", s.toString());
		Assert.assertEquals(Long.MAX_VALUE, s.getSignedValue());
		Assert.assertEquals(Long.MAX_VALUE, s.getUnsignedValue());

		s = new Scalar(64, -1, false);
		Assert.assertEquals("0xffffffffffffffff", s.toString(16, true, false, "0x", ""));
		Assert.assertEquals("0xffffffffffffffff", s.toString(16, false, true, "0x", ""));
		Assert.assertEquals("18446744073709551615", s.toString(10, true, false, "", ""));
		Assert.assertEquals("0xffffffffffffffff", s.toString());
		Assert.assertEquals(-1, s.getSignedValue());
		Assert.assertEquals(-1, s.getUnsignedValue());

		s = new Scalar(64, Long.MIN_VALUE, false);
		Assert.assertEquals("0x8000000000000000", s.toString(16, true, false, "0x", ""));
		Assert.assertEquals("0x8000000000000000", s.toString(16, false, true, "0x", ""));
		Assert.assertEquals("9223372036854775808", s.toString(10, true, false, "", ""));
		Assert.assertEquals("0x8000000000000000", s.toString());
		Assert.assertEquals(Long.MIN_VALUE, s.getSignedValue());
		Assert.assertEquals(Long.MIN_VALUE, s.getUnsignedValue());

		Assert.assertFalse(s.equals(new Scalar(64, Long.MIN_VALUE, true)));

		s = new Scalar(64, Long.MAX_VALUE, false);
		Assert.assertEquals("0x7fffffffffffffff", s.toString(16, true, false, "0x", ""));
		Assert.assertEquals("0x7fffffffffffffff", s.toString(16, false, true, "0x", ""));
		Assert.assertEquals("9223372036854775807", s.toString(10, true, false, "", ""));
		Assert.assertEquals("0x7fffffffffffffff", s.toString());
		Assert.assertEquals(Long.MAX_VALUE, s.getSignedValue());
		Assert.assertEquals(Long.MAX_VALUE, s.getUnsignedValue());

		Assert.assertTrue(s.equals(new Scalar(64, Long.MAX_VALUE, true)));
	}

	@Test
	public void testScalar8() {

		Scalar s = null;

		s = new Scalar(8, -1, true);
		Assert.assertEquals("0xff", s.toString(16, true, false, "0x", ""));
		Assert.assertEquals("-0x1", s.toString(16, false, true, "0x", ""));
		Assert.assertEquals("255", s.toString(10, true, false, "", ""));
		Assert.assertEquals("-0x1", s.toString());
		Assert.assertEquals(-1, s.getSignedValue());
		Assert.assertEquals(255, s.getUnsignedValue());

		s = new Scalar(8, Byte.MIN_VALUE, true);
		Assert.assertEquals("0x80", s.toString(16, true, false, "0x", ""));
		Assert.assertEquals("-0x80", s.toString(16, false, true, "0x", ""));
		Assert.assertEquals("128", s.toString(10, true, false, "", ""));
		Assert.assertEquals("-0x80", s.toString());
		Assert.assertEquals(Byte.MIN_VALUE, s.getSignedValue());
		Assert.assertEquals(128, s.getUnsignedValue());

		s = new Scalar(8, Byte.MAX_VALUE, true);
		Assert.assertEquals("0x7f", s.toString(16, true, false, "0x", ""));
		Assert.assertEquals("0x7f", s.toString(16, false, true, "0x", ""));
		Assert.assertEquals("127", s.toString(10, true, false, "", ""));
		Assert.assertEquals("0x7f", s.toString());
		Assert.assertEquals(Byte.MAX_VALUE, s.getSignedValue());
		Assert.assertEquals(Byte.MAX_VALUE, s.getUnsignedValue());

		s = new Scalar(8, -1, false);
		Assert.assertEquals("0xff", s.toString(16, true, false, "0x", ""));
		Assert.assertEquals("0xff", s.toString(16, false, true, "0x", ""));
		Assert.assertEquals("255", s.toString(10, true, false, "", ""));
		Assert.assertEquals("0xff", s.toString());
		Assert.assertEquals(-1, s.getSignedValue());
		Assert.assertEquals(255, s.getUnsignedValue());

		s = new Scalar(8, Byte.MIN_VALUE, false);
		Assert.assertEquals("0x80", s.toString(16, true, false, "0x", ""));
		Assert.assertEquals("0x80", s.toString(16, false, true, "0x", ""));
		Assert.assertEquals("128", s.toString(10, true, false, "", ""));
		Assert.assertEquals("0x80", s.toString());
		Assert.assertEquals(Byte.MIN_VALUE, s.getSignedValue());
		Assert.assertEquals(128, s.getUnsignedValue());

		s = new Scalar(8, Byte.MAX_VALUE, false);
		Assert.assertEquals("0x7f", s.toString(16, true, false, "0x", ""));
		Assert.assertEquals("0x7f", s.toString(16, false, true, "0x", ""));
		Assert.assertEquals("127", s.toString(10, true, false, "", ""));
		Assert.assertEquals("0x7f", s.toString());
		Assert.assertEquals(Byte.MAX_VALUE, s.getSignedValue());
		Assert.assertEquals(Byte.MAX_VALUE, s.getUnsignedValue());

	}

	@Test
	public void testIgnoreExtraBits() {
		// tests that extra bits in the long initial value are ignored when creating value
		assertEquals(0x22, new Scalar(8, 0x1122).getValue());
		assertEquals(0x1122, new Scalar(16, 0x1122).getValue());
	}

	@Test
	public void testLeftShiftByMoreThan32() {
		// tests that the impl doesn't mess up when dealing with masks / bits that are larger
		// than what can be held in a 32bit int.  (eg. 1 << 33 is an error, needs to be 1L << 33)
		assertEquals(55, new Scalar(32, 55).getSignedValue());
		assertEquals(55, new Scalar(33, 55).getSignedValue()); // would fail if shift-by-32 error

		assertEquals(0x8000, new Scalar(32, 0x8000).getSignedValue());
		assertEquals(0x8000, new Scalar(48, 0x8000).getSignedValue()); // would fail if shift-by-32 error

		assertEquals(0x40000000L, new Scalar(32, 0x40000000L).getSignedValue());
		assertEquals(0x40000000L, new Scalar(63, 0x40000000L).getSignedValue()); // would fail

		assertFalse(new Scalar(64, 0x1_0000_0000L).testBit(31));
		assertTrue(new Scalar(64, 0x1_0000_0000L).testBit(32));
		assertFalse(new Scalar(64, 0x1_0000_0000L).testBit(33));
	}

	@Test
	public void testGetBigInt() {
		assertEquals(BigInteger.valueOf(-1), new Scalar(8, 0xffL).getBigInteger());
		assertEquals(BigInteger.valueOf(-1), new Scalar(32, 0xffffffffL).getBigInteger());
		assertEquals(BigInteger.valueOf(-1), new Scalar(64, -1L).getBigInteger());

		assertEquals(BigInteger.valueOf(Byte.MIN_VALUE), new Scalar(8, 0x80L).getBigInteger());
		assertEquals(BigInteger.valueOf(Short.MIN_VALUE), new Scalar(16, 0x8000L).getBigInteger());
		assertEquals(BigInteger.valueOf(Integer.MIN_VALUE),
			new Scalar(32, 0x80000000L).getBigInteger());
		assertEquals(BigInteger.valueOf(Long.MIN_VALUE),
			new Scalar(64, Long.MIN_VALUE).getBigInteger());

		assertEquals(BigInteger.valueOf(0x80L), new Scalar(9, 0x80L).getBigInteger());
		assertEquals(BigInteger.valueOf(0x8000L), new Scalar(17, 0x8000L).getBigInteger());
		assertEquals(BigInteger.valueOf(0x8000_0000L),
			new Scalar(33, 0x8000_0000L).getBigInteger());
		assertEquals(BigInteger.valueOf(0x1_8000_0000L),
			new Scalar(34, 0x1_8000_0000L).getBigInteger());
	}

	@Test
	public void testTestBit() {
		Scalar scalar = new Scalar(64, -1, true);
		for (int bitnum = 0; bitnum < 64; bitnum++) {
			assertTrue(scalar.testBit(bitnum));
		}

		// test top half of int64 are 0's, bottom half are 1's
		scalar = new Scalar(64, NumericUtilities.MAX_UNSIGNED_INT32_AS_LONG);
		for (int bitnum = 0; bitnum < 32; bitnum++) {
			assertTrue(scalar.testBit(bitnum));
		}
		for (int bitnum = 32; bitnum < 64; bitnum++) {
			assertFalse(scalar.testBit(bitnum));
		}
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testScalar0bitsTestBit() {
		Scalar scalar = new Scalar(0, 0);
		scalar.testBit(0);
		fail("Scalar testBit(0) should fail");
	}

}
