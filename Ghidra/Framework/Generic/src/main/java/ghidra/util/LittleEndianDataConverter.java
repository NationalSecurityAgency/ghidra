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

import java.math.BigInteger;
import java.util.Objects;

/**
 * 
 * Helper class to convert a byte array to a Java primitive in Little endian
 * order, and to convert a primitive to a byte array.
 */

public class LittleEndianDataConverter implements DataConverter {
	public static final LittleEndianDataConverter INSTANCE = new LittleEndianDataConverter();

	private static final long serialVersionUID = 1L;

	/**
	 * Don't use this constructor to create new instances of this class.  Use the static {@link #INSTANCE} instead
	 * or {@link DataConverter#getInstance(boolean)}
	 */
	public LittleEndianDataConverter() {
		// empty
	}

	@Override
	public short getShort(byte[] b, int offset) {
		Objects.checkFromIndexSize(offset, Short.BYTES, b.length);

		return (short) (((b[offset + 1] & 0xff) << 8) | (b[offset] & 0xff));
	}

	@Override
	public int getInt(byte[] b, int offset) {
		Objects.checkFromIndexSize(offset, Integer.BYTES, b.length);

		int v = b[offset + 3];
		for (int i = 2; i >= 0; i--) {
			v = (v << 8) | (b[offset + i] & 0xff);
		}
		return v;
	}

	@Override
	public long getLong(byte[] b, int offset) {
		Objects.checkFromIndexSize(offset, Long.BYTES, b.length);

		long v = b[offset + 7];
		for (int i = 6; i >= 0; i--) {
			v = (v << 8) | (b[offset + i] & 0xff);
		}
		return v;
	}

	@Override
	public long getValue(byte[] b, int offset, int size) {
		Objects.checkFromIndexSize(offset, size, b.length);
		Objects.checkIndex(size, Long.BYTES + 1);

		long val = 0;
		for (int i = size - 1; i >= 0; i--) {
			val = (val << 8) | (b[offset + i] & 0xff);
		}
		return val;
	}

	@Override
	public BigInteger getBigInteger(byte[] b, int offset, int size, boolean signed) {
		Objects.checkFromIndexSize(offset, size, b.length);

		int msbIndex = 0;
		if (!signed) {
			// prepend 0 byte
			++size;
			msbIndex = 1;
		}
		int bIndex = 0;
		byte[] bytes = new byte[size];
		for (int i = size - 1; i >= msbIndex; i--) {
			bytes[i] = b[offset + bIndex++];
		}
		return new BigInteger(bytes);
	}

	@Override
	public void putShort(byte[] b, int offset, short value) {
		Objects.checkFromIndexSize(offset, Short.BYTES, b.length);

		b[offset + 1] = (byte) (value >> 8);
		b[offset] = (byte) (value & 0xff);
	}

	@Override
	public void putInt(byte[] b, int offset, int value) {
		Objects.checkFromIndexSize(offset, Integer.BYTES, b.length);

		b[offset] = (byte) (value);
		for (int i = 1; i < 4; i++) {
			value >>= 8;
			b[offset + i] = (byte) (value);
		}
	}

	@Override
	public void putValue(long value, int size, byte[] b, int offset) {
		Objects.checkFromIndexSize(offset, size, b.length);
		Objects.checkIndex(size, Long.BYTES + 1);

		for (int i = 0; i < size; i++) {
			b[offset + i] = (byte) value;
			value >>= 8;
		}
	}

	@Override
	public void putBigInteger(byte[] b, int offset, int size, BigInteger value) {
		Objects.checkFromIndexSize(offset, size, b.length);

		int fillIndex = offset + size - 1; // start fill from MSB
		int srcIndex;

		byte[] valBytes = value.toByteArray();
		if (valBytes.length >= size) {
			srcIndex = valBytes.length - size;
		}
		else {
			srcIndex = 0;
			byte signbits = (value.signum() < 0) ? (byte) 0xff : 0;
			for (int i = valBytes.length; i < size; i++) {
				b[fillIndex--] = signbits;
			}
		}
		for (int i = srcIndex; i < valBytes.length; i++) {
			b[fillIndex--] = valBytes[i];
		}
	}

}
