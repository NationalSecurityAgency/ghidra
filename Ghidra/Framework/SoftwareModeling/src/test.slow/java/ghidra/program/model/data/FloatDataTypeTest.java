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

import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.util.LittleEndianDataConverter;

public class FloatDataTypeTest extends AbstractGTest {

	private byte[] getBytes(long value, int size) {
		byte[] bytes = new byte[size];
		LittleEndianDataConverter.INSTANCE.getBytes(value, size, bytes, 0);
		return bytes;
	}

	@Test
	public void testFloat4Extremes() {

		int bits = Float.floatToRawIntBits(Float.NaN);
		byte[] bytes = getBytes(bits, 4);
		Object value =
			Float4DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, false), null, 10);
		assertEquals(Float.NaN, value);

		bits = Float.floatToRawIntBits(Float.POSITIVE_INFINITY);
		bytes = getBytes(bits, 4);
		value =
			Float4DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, false), null, 10);
		assertEquals(Float.POSITIVE_INFINITY, value);

		bits = Float.floatToRawIntBits(Float.NEGATIVE_INFINITY);
		bytes = getBytes(bits, 4);
		value =
			Float4DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, false), null, 10);
		assertEquals(Float.NEGATIVE_INFINITY, value);

		bits = Float.floatToRawIntBits(0F);
		bytes = getBytes(bits, 4);
		value =
			Float4DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, false), null, 10);
		assertEquals(0F, value);

		bits = Float.floatToRawIntBits(1F);
		bytes = getBytes(bits, 4);
		value =
			Float4DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, false), null, 10);
		assertEquals(1F, value);

		bits = Float.floatToRawIntBits(-1F);
		bytes = getBytes(bits, 4);
		value =
			Float4DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, false), null, 10);
		assertEquals(-1F, value);

		bits = Float.floatToRawIntBits(555.555F);
		bytes = getBytes(bits, 4);
		value =
			Float4DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, false), null, 10);
		assertEquals(555.555F, value);

		bits = Float.floatToRawIntBits(-555.555F);
		bytes = getBytes(bits, 4);
		value =
			Float4DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, false), null, 10);
		assertEquals(-555.555F, value);

	}

	@Test
	public void testFloat8Extremes() {

		long bits = Double.doubleToRawLongBits(Double.NaN);
		byte[] bytes = getBytes(bits, 8);
		Object value =
			Float8DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, false), null, 10);
		assertEquals(Double.NaN, value);

		bits = Double.doubleToRawLongBits(Double.POSITIVE_INFINITY);
		bytes = getBytes(bits, 8);
		value =
			Float8DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, false), null, 10);
		assertEquals(Double.POSITIVE_INFINITY, value);

		bits = Double.doubleToRawLongBits(Double.NEGATIVE_INFINITY);
		bytes = getBytes(bits, 8);
		value =
			Float8DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, false), null, 10);
		assertEquals(Double.NEGATIVE_INFINITY, value);

		bits = Double.doubleToRawLongBits(0D);
		bytes = getBytes(bits, 8);
		value =
			Float8DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, false), null, 10);
		assertEquals(0D, value);

		bits = Double.doubleToRawLongBits(1D);
		bytes = getBytes(bits, 8);
		value =
			Float8DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, false), null, 10);
		assertEquals(1D, value);

		bits = Double.doubleToRawLongBits(-1D);
		bytes = getBytes(bits, 8);
		value =
			Float8DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, false), null, 10);
		assertEquals(-1D, value);

		bits = Double.doubleToRawLongBits(555.555D);
		bytes = getBytes(bits, 8);
		value =
			Float8DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, false), null, 10);
		assertEquals(555.555D, value);

		bits = Double.doubleToRawLongBits(-555.555D);
		bytes = getBytes(bits, 8);
		value =
			Float8DataType.dataType.getValue(new ByteMemBufferImpl(null, bytes, false), null, 10);
		assertEquals(-555.555D, value);

	}

}
