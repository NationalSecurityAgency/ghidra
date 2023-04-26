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

import static org.junit.Assert.*;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.pcode.floatformat.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;

public class Float10DataTypeTest extends AbstractGTest {

	@Test
	public void testGetValue() {

		FloatFormat ff = FloatFormatFactory.getFloatFormat(10);

		byte[] bytes = bytes(0x7f, 0xff, 0, 0, 0, 0, 0, 0, 0, 0); // 0x7fff0000000000000000 = +infinity
		BigFloat value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals(ff.getBigInfinity(false), value);
		Assert.assertEquals("+Infinity", ff.toDecimalString(value, true));

		bytes = bytes(0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0); // 0xffff0000000000000000 = -infinity
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals(ff.getBigInfinity(true), value);
		Assert.assertEquals("-Infinity", ff.toDecimalString(value, true));

		bytes = bytes(0x7f, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0); // 0x7fff8000000000000000 = NaN
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals(ff.getBigNaN(false), value);
		Assert.assertEquals("NaN", ff.toDecimalString(value, true));

		// small values
		// initially produced by gcc for little-edian then byte-reversed here

		bytes = bytes(0x3c, 1, 0x80, 0, 0, 0, 0, 0, 0, 0);
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals("2.22507385850720138E-308",
			ff.toDecimalString(value, true));

		bytes = bytes(0xbc, 1, 0x80, 0, 0, 0, 0, 0, 0, 0);
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals("-2.22507385850720138E-308",
			ff.toDecimalString(value, true));

		// Really small values - subnormal minimum for decode only - approaches zero

		bytes = bytes(0, 0, 0, 0, 0, 0, 0, 0, 0, 1);
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		assertEquals(ff.minValue, value);
		Assert.assertEquals("3.6E-4951", ff.toDecimalString(value, true));

		bytes = bytes(0x80, 0, 0, 0, 0, 0, 0, 0, 0, 1);
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals("-3.6E-4951", ff.toDecimalString(value, true));

		// Really big values maximum - approaches -infinity

		bytes = bytes(0x7f, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		assertEquals(ff.maxValue, value);
		Assert.assertEquals("1.18973149535723177E+4932", ff.toDecimalString(value, true));

		bytes = bytes(0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals("-1.18973149535723177E+4932", ff.toDecimalString(value, true));

		// Values within the range of Double

		// pi - 3.14159265358979323
		// initially produced by gcc for little-edian then byte-reversed here

		bytes = bytes(0x40, 0, 0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc0, 0);
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals("3.14159265358979312", ff.toDecimalString(value, true));

		bytes = bytes(0xc0, 0, 0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc0, 0);
		value =
			Float10DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, true), null, 10);
		Assert.assertEquals("-3.14159265358979312", ff.toDecimalString(value, true));

	}

	private static MemBuffer buf(boolean bigEndian, int... vals) {
		return new ByteMemBufferImpl(Address.NO_ADDRESS, bytes(vals), bigEndian);
	}

	private static final MemBuffer BE = buf(true, 0);

	@Test
	public void testEncodeValue() throws Exception {

		FloatFormat ff = FloatFormatFactory.getFloatFormat(10);

		byte[] bytes = bytes(0x7f, 0xff, 0, 0, 0, 0, 0, 0, 0, 0); // 0x7fff0000000000000000 = +infinity
		assertArrayEquals(bytes,
			Float10DataType.dataType.encodeValue(ff.getBigFloat("+Infinity"), BE, null, -1));

		bytes = bytes(0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0); // 0xffff0000000000000000 = -infinity
		assertArrayEquals(bytes,
			Float10DataType.dataType.encodeValue(ff.getBigFloat("-Infinity"), BE, null, -1));

		bytes = bytes(0x7f, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0); // 0x7fff8000000000000000 = NaN
		assertArrayEquals(bytes,
			Float10DataType.dataType.encodeValue(ff.getBigFloat("NaN"), BE, null, -1));

		// NOTE: Multiple byte[] values can render the same decimal string

		bytes = Float10DataType.dataType
				.encodeValue(ff.getBigFloat("5.04315471466814026E-4932"), BE, null, -1);
		assertEquals("5.04315471466814026E-4932", Float10DataType.dataType
				.getRepresentation(new ByteMemBufferImpl(null, bytes, true), null, -1));

		bytes = Float10DataType.dataType.encodeValue(ff.getBigFloat("-5.04315471466814026E-4932"),
			BE, null, -1);
		assertEquals("-5.04315471466814026E-4932", Float10DataType.dataType
				.getRepresentation(new ByteMemBufferImpl(null, bytes, true), null, -1));

		bytes = Float10DataType.dataType
				.encodeValue(ff.getBigFloat("8.92298621517923824E+4931"), BE, null, -1);
		assertEquals("8.92298621517923824E+4931", Float10DataType.dataType
				.getRepresentation(new ByteMemBufferImpl(null, bytes, true), null, -1));

		bytes = Float10DataType.dataType.encodeValue(ff.getBigFloat("-8.92298621517923824E+4931"),
			BE, null, -1);
		assertEquals("-8.92298621517923824E+4931", Float10DataType.dataType
				.getRepresentation(new ByteMemBufferImpl(null, bytes, true), null, -1));

	}

}
