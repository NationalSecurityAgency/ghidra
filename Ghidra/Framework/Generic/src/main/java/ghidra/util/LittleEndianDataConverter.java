/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

/**
 * 
 * Helper class to convert a byte array to a Java primitive in Little endian
 * order, and to convert a primitive to a byte array.
 */

public class LittleEndianDataConverter implements DataConverter {
	public static LittleEndianDataConverter INSTANCE = new LittleEndianDataConverter();
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Constructor for BigEndianDataConverter.
	 */
	public LittleEndianDataConverter() {
	}

	/**
	 * @see DataConverter#getShort(byte[])
	 */
	public final short getShort(byte[] b) {
		return getShort(b, 0);
	}

	/**
	 * @see DataConverter#getShort(byte[], int)
	 */
	public short getShort(byte[] b, int offset) {
		return (short) (((b[offset + 1] & 0xff) << 8) | (b[offset] & 0xff));
	}

	/**
	 * @see DataConverter#getInt(byte[])
	 */
	public final int getInt(byte[] b) {
		return getInt(b, 0);
	}

	/**
	 * @see DataConverter#getInt(byte[], int)
	 */
	public int getInt(byte[] b, int offset) {
		int v = b[offset + 3];
		for (int i = 2; i >= 0; i--) {
			v = (v << 8) | (b[offset + i] & 0xff);
		}
		return v;
	}

	/**
	 * @see DataConverter#getLong(byte[])
	 */
	public final long getLong(byte[] b) {
		return getLong(b, 0);
	}

	/**
	 * @see DataConverter#getLong(byte[], int)
	 */
	public long getLong(byte[] b, int offset) {
		long v = b[offset + 7];
		for (int i = 6; i >= 0; i--) {
			v = (v << 8) | (b[offset + i] & 0xff);
		}
		return v;
	}

	/**
	 * @see ghidra.util.DataConverter#getValue(byte[], int)
	 */
	public long getValue(byte[] b, int size) {
		return getValue(b, 0, size);
	}

	/**
	 * @see ghidra.util.DataConverter#getValue(byte[], int, int)
	 */
	public long getValue(byte[] b, int offset, int size) {
		if (size > 8) {
			throw new IndexOutOfBoundsException("size exceeds sizeof long: " + size);
		}
		long val = 0;
		for (int i = size - 1; i >= 0; i--) {
			val = (val << 8) | (b[offset + i] & 0xff);
		}
		return val;
	}

	@Override
	public final BigInteger getBigInteger(byte[] b, int size, boolean signed) {
		return getBigInteger(b, 0, size, signed);
	}

	@Override
	public final BigInteger getBigInteger(byte[] b, int offset, int size, boolean signed) {
		if ((size + offset) > b.length) {
			throw new IndexOutOfBoundsException("insufficient bytes");
		}
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

	/**
	 * @see DataConverter#getBytes(short, byte[])
	 */
	public final void getBytes(short value, byte[] b) {
		getBytes(value, b, 0);
	}

	/**
	 * @see DataConverter#getBytes(short, byte[], int)
	 */
	public void getBytes(short value, byte[] b, int offset) {
		b[offset + 1] = (byte) (value >> 8);
		b[offset] = (byte) (value & 0xff);
	}

	/**
	 * @see DataConverter#getBytes(int, byte[])
	 */
	public final void getBytes(int value, byte[] b) {
		getBytes(value, b, 0);
	}

	/**
	 * @see DataConverter#getBytes(int, byte[], int)
	 */
	public void getBytes(int value, byte[] b, int offset) {
		b[offset] = (byte) (value);
		for (int i = 1; i < 4; i++) {
			value >>= 8;
			b[offset + i] = (byte) (value);
		}
	}

	/**
	 * @see DataConverter#getBytes(long, byte[])
	 */
	public final void getBytes(long value, byte[] b) {
		getBytes(value, 8, b, 0);
	}

	/**
	 * @see DataConverter#getBytes(long, byte[], int)
	 */
	public void getBytes(long value, byte[] b, int offset) {
		getBytes(value, 8, b, offset);
	}

	/**
	 * @see ghidra.util.DataConverter#getBytes(long, int, byte[], int)
	 */
	public void getBytes(long value, int size, byte[] b, int offset) {
		for (int i = 0; i < size; i++) {
			b[offset + i] = (byte) value;
			value >>= 8;
		}
	}

	/**
	 * @see ghidra.util.DataConverter#putInt(byte[], int, int)
	 */
	public final void putInt(byte[] b, int offset, int value) {
		getBytes(value, b, offset);
	}

	/**
	 * @see ghidra.util.DataConverter#putInt(byte[], int)
	 */
	public final void putInt(byte[] b, int value) {
		getBytes(value, b);
	}

	/**
	 * @see ghidra.util.DataConverter#putLong(byte[], int, long)
	 */
	public final void putLong(byte[] b, int offset, long value) {
		getBytes(value, b, offset);
	}

	/**
	 * @see ghidra.util.DataConverter#putLong(byte[], long)
	 */
	public final void putLong(byte[] b, long value) {
		getBytes(value, b);
	}

	/**
	 * @see ghidra.util.DataConverter#putShort(byte[], int, short)
	 */
	public final void putShort(byte[] b, int offset, short value) {
		getBytes(value, b, offset);
	}

	/**
	 * @see ghidra.util.DataConverter#putShort(byte[], short)
	 */
	public final void putShort(byte[] b, short value) {
		getBytes(value, b);
	}

	/**
	 * @see ghidra.util.DataConverter#getBytes(int)
	 */
	public byte[] getBytes(int value) {
		byte[] bytes = new byte[4];
		getBytes(value, bytes);
		return bytes;
	}

	/**
	 * @see ghidra.util.DataConverter#getBytes(long)
	 */
	public byte[] getBytes(long value) {
		byte[] bytes = new byte[8];
		getBytes(value, bytes);
		return bytes;
	}

	/**
	 * @see ghidra.util.DataConverter#getBytes(short)
	 */
	public byte[] getBytes(short value) {
		byte[] bytes = new byte[2];
		getBytes(value, bytes);
		return bytes;
	}

	@Override
	public byte[] getBytes(BigInteger value, int size) {
		byte[] bytes = new byte[size];
		putBigInteger(bytes, 0, size, value);
		return bytes;
	}

	@Override
	public void getBytes(BigInteger value, int size, byte[] b, int offset) {
		putBigInteger(b, offset, size, value);
	}

	@Override
	public void putBigInteger(byte[] b, int offset, int size, BigInteger value) {

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

	@Override
	public void putBigInteger(byte[] b, int size, BigInteger value) {
		putBigInteger(b, 0, size, value);
	}

}
