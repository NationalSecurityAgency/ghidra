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
 * Helper class to convert a byte array to Java primitives and primitives to a
 * byte array in Big endian.
 * 
 * 
 * 
 */
public class BigEndianDataConverter implements DataConverter {
	public static final BigEndianDataConverter INSTANCE = new BigEndianDataConverter();

	private static final long serialVersionUID = 1L;

	/**
	 * Don't use this constructor to create new instances of this class.  Use the static {@link #INSTANCE} instead.
	 */
	public BigEndianDataConverter() {
		// empty
	}

	@Override
	public short getShort(byte[] b, int offset) {
		Objects.checkFromIndexSize(offset, Short.BYTES, b.length);

		return (short) (((b[offset] & 0xff) << 8) | (b[offset + 1] & 0xff));
	}

	@Override
	public int getInt(byte[] b, int offset) {
		Objects.checkFromIndexSize(offset, Integer.BYTES, b.length);

		int v = b[offset];
		for (int i = 1; i < 4; i++) {
			v = (v << 8) | (b[offset + i] & 0xff);
		}
		return v;
	}

	@Override
	public long getLong(byte[] b, int offset) {
		Objects.checkFromIndexSize(offset, Long.BYTES, b.length);

		long v = b[offset];
		for (int i = 1; i < 8; i++) {
			v = (v << 8) | (b[offset + i] & 0xff);
		}
		return v;
	}

	@Override
	public long getValue(byte[] b, int offset, int size) {
		Objects.checkFromIndexSize(offset, size, b.length);
		Objects.checkIndex(size, Long.BYTES + 1);

		long val = 0;
		for (int i = 0; i < size; i++) {
			val = (val << 8) | (b[offset + i] & 0xff);
		}
		return val;
	}

	@Override
	public final BigInteger getBigInteger(byte[] b, int offset, int size, boolean signed) {
		Objects.checkFromIndexSize(offset, size, b.length);

		if (offset != 0 || size != b.length) {
			int index = 0;
			if (!signed && b[offset] < 0) {
				// keep unsigned - prepend 0 byte
				++size;
				index = 1;
			}
			byte[] bytes = new byte[size];
			System.arraycopy(b, offset, bytes, index, size - index);
			b = bytes;
		}
		else if (!signed && b[0] < 0) {
			// keep unsigned - prepend 0 byte
			byte[] bytes = new byte[size + 1];
			System.arraycopy(b, 0, bytes, 1, size);
			b = bytes;
		}
		return new BigInteger(b);
	}

	@Override
	public void putShort(byte[] b, int offset, short value) {
		Objects.checkFromIndexSize(offset, Short.BYTES, b.length);

		b[offset] = (byte) (value >> 8);
		b[offset + 1] = (byte) (value & 0xff);
	}

	@Override
	public void putInt(byte[] b, int offset, int value) {
		Objects.checkFromIndexSize(offset, Integer.BYTES, b.length);

		b[offset + 3] = (byte) (value);
		for (int i = 2; i >= 0; i--) {
			value >>= 8;
			b[offset + i] = (byte) (value);
		}
	}

	@Override
	public void putValue(long value, int size, byte[] b, int offset) {
		Objects.checkFromIndexSize(offset, size, b.length);
		Objects.checkIndex(size, Long.BYTES + 1);

		for (int i = size - 1; i >= 0; i--) {
			b[offset + i] = (byte) value;
			value >>= 8;
		}
	}

	@Override
	public void putBigInteger(byte[] b, int offset, int size, BigInteger value) {
		Objects.checkFromIndexSize(offset, size, b.length);

		int fillIndex = offset; // start fill from MSB
		int srcIndex;

		byte[] valBytes = value.toByteArray();
		int fillCnt = valBytes.length;

		if (valBytes.length >= size) {
			srcIndex = valBytes.length - size;
			fillCnt = valBytes.length - srcIndex;
		}
		else {
			srcIndex = 0;
			byte signbits = (value.signum() < 0) ? (byte) 0xff : 0;
			for (int i = valBytes.length; i < size; i++) {
				b[fillIndex++] = signbits;
			}
		}
		System.arraycopy(valBytes, srcIndex, b, fillIndex, fillCnt);
	}

}
