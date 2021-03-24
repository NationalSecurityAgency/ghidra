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

import java.math.*;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.pcode.floatformat.FloatFormat;
import ghidra.program.model.mem.ByteMemBufferImpl;

public class Float10DataTypeTest extends AbstractGTest {

	@Test
	public void testGetValue() {

		byte[] bytes = bytes(0x7f, 0xff, 0, 0, 0, 0, 0, 0, 0, 0); // 0x7fff0000000000000000 = +infinity
		Object value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals(FloatFormat.BIG_POSITIVE_INFINITY, value);

		bytes = bytes(0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0); // 0xffff0000000000000000 = -infinity
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals(FloatFormat.BIG_NEGATIVE_INFINITY, value);

		bytes = bytes(0x7f, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0); // 0x7fff8000000000000000 = NaN
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals(FloatFormat.BIG_NaN, value);

		// Really small values

		MathContext mc = new MathContext(18, RoundingMode.UP);

		bytes = bytes(0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0); // 0x00018000000000000000 = approaches 0
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals("5.04315471466814026E-4932", ((BigDecimal) value).round(mc).toString());

		bytes = bytes(0x80, 1, 0x80, 0, 0, 0, 0, 0, 0, 0); // 0x00018000000000000000 = approaches 0
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals("-5.04315471466814026E-4932",
			((BigDecimal) value).round(mc).toString());

		// Really big values

		bytes = bytes(0x7f, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0); // 0x7ffe8000000000000000 = approaches +infinity
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals("8.92298621517923824E+4931", ((BigDecimal) value).round(mc).toString());

		bytes = bytes(0xff, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0); // 0x7ffe8000000000000000 = approaches -infinity
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals("-8.92298621517923824E+4931",
			((BigDecimal) value).round(mc).toString());

		// Values within the range of Double

		bytes = bytes(0x40, 1, 0x20, 0, 0, 0, 0, 0, 0, 0); // 0x40002000000000000000 = approaches -infinity
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals(BigDecimal.valueOf(4.5), ((BigDecimal) value).stripTrailingZeros());

		bytes = bytes(0xc0, 1, 0x20, 0, 0, 0, 0, 0, 0, 0); // 0x40002000000000000000 = approaches -infinity
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals(BigDecimal.valueOf(-4.5), ((BigDecimal) value).stripTrailingZeros());

	}

}
