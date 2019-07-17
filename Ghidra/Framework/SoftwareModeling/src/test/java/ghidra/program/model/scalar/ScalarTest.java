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

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class ScalarTest extends AbstractGenericTest {

	public ScalarTest() {
		super();
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
}
