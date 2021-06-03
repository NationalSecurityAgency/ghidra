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

import java.io.Serializable;
import java.math.BigInteger;

/**
 * Stateless helper classes with static singleton instances that contain methods to convert
 * Java numeric types to and from their raw form in a byte array.
 * <p>
 * 
 */
public interface DataConverter extends Serializable {

	/**
	 * Returns the correct DataConverter static instance for the requested endian-ness.
	 * 
	 * @param isBigEndian boolean flag, true means big endian
	 * @return static DataConverter instance
	 */
	public static DataConverter getInstance(boolean isBigEndian) {
		return isBigEndian ? BigEndianDataConverter.INSTANCE : LittleEndianDataConverter.INSTANCE;
	}

	/**
	 * Returns the endianess of this DataConverter instance.
	 * 
	 * @return boolean flag, true means big-endian
	 */
	default boolean isBigEndian() {
		return this instanceof BigEndianDataConverter;
	}

	/**
	 * Get the short value from the given byte array.
	 * @param b array containing bytes
	 * @return signed short value from the beginning of the specified array
	 * @throws IndexOutOfBoundsException if byte array size is less than 2.
	 */
	default short getShort(byte[] b) {
		return getShort(b, 0);
	}

	/**
	 * Get the short value from the given byte array.
	 * 
	 * @param b array containing bytes
	 * @param offset offset into byte array for getting the short
	 * @return signed short value
	 * @throws IndexOutOfBoundsException if byte array size is less than offset+2
	 */
	short getShort(byte[] b, int offset);

	/**
	 * Get the int value from the given byte array.
	 * 
	 * @param b array containing bytes
	 * @return signed int value from the beginning of the specified array
	 * @throws IndexOutOfBoundsException if byte array size is less than 4
	 */
	default int getInt(byte[] b) {
		return getInt(b, 0);
	}

	/**
	 * Get the int value from the given byte array.
	 * 
	 * @param b array containing bytes
	 * @param offset offset into byte array for getting the int
	 * @return signed int value
	 * @throws IndexOutOfBoundsException if byte array size is less than offset+4
	 */
	int getInt(byte[] b, int offset);

	/**
	 * Get the long value from the given byte array.
	 * 
	 * @param b array containing bytes
	 * @return signed long value from the beginning of the specified array
	 * @throws IndexOutOfBoundsException if byte array size is less than 8
	 */
	default long getLong(byte[] b) {
		return getLong(b, 0);
	}

	/**
	 * Get the long value from the given byte array.
	 * 
	 * @param b array containing bytes
	 * @param offset offset into byte array for getting the long
	 * @return signed long value
	 * @throws IndexOutOfBoundsException if byte array size is less than offset+8
	 */
	long getLong(byte[] b, int offset);

	/**
	 * Get the <b>unsigned</b> value from the given byte array using the specified 
	 * integer size, returned as a long.
	 * <p>
	 * Values with a size less than sizeof(long) will <b>not</b> have their sign bit
	 * extended and therefore will appear as an 'unsigned' value.
	 * <p>
	 * Casting the 'unsigned' long value to the correctly sized smaller 
	 * java primitive will cause the value to appear as a signed value.
	 * <p> 
	 * Values of size 8 (ie. longs) will be signed. 
	 * 
	 * @param b array containing bytes
	 * @param size number of bytes (1 - 8) to use from array at offset 0
	 * @return unsigned value from the beginning of the specified array
	 * @throws IndexOutOfBoundsException if byte array size is less than specified size
	 */
	default long getValue(byte[] b, int size) {
		return getValue(b, 0, size);
	}

	/**
	 * Get the <b>unsigned</b> value from the given byte array using the specified 
	 * integer size, returned as a long.
	 * <p>
	 * Values with a size less than sizeof(long) will <b>not</b> have their sign bit
	 * extended and therefore will appear as an 'unsigned' value.
	 * <p>
	 * Casting the 'unsigned' long value to the correctly sized smaller 
	 * java primitive will cause the value to appear as a signed value. 
	 * <p>
	 * Values of size 8 (ie. longs) will be signed. 
	 * 
	 * @param b array containing bytes
	 * @param size number of bytes (1 - 8) to use from array
	 * @param offset offset into byte array for getting the long
	 * @return unsigned value
	 * @throws IndexOutOfBoundsException if byte array size is
	 * less than offset+size or size is greater than 8 (sizeof long)
	 */
	long getValue(byte[] b, int offset, int size);

	/**
	 * Get the <b>signed</b> value from the given byte array using the specified 
	 * integer size, returned as a long.
	 * <p>
	 * Values with a size less than sizeof(long) will have their sign bit
	 * extended.
	 * 
	 * @param b array containing bytes
	 * @param size number of bytes (1 - 8) to use from array at offset 0
	 * @return signed value from the beginning of the specified array 
	 * @throws IndexOutOfBoundsException if byte array size is less than specified size
	 */
	default long getSignedValue(byte[] b, int size) {
		return getSignedValue(b, 0, size);
	}

	/**
	 * Get the <b>signed</b> value from the given byte array using the specified 
	 * integer size, returned as a long.
	 * <p>
	 * Values with a size less than sizeof(long) will have their sign bit
	 * extended.
	 * 
	 * @param b array containing bytes
	 * @param size number of bytes (1 - 8) to use from array
	 * @param offset offset into byte array for getting the long
	 * @return signed value
	 * @throws IndexOutOfBoundsException if byte array size is
	 * less than offset+size or size is greater than 8 (sizeof long)
	 */
	default long getSignedValue(byte[] b, int offset, int size) {
		long val = getValue(b, offset, size);

		int shiftBits = (8 /*sizeof(long)*/ - size) * 8;

		// this little bit of magic will sign-extend the value
		val = val << shiftBits;
		val = val >> shiftBits;
		return val;
	}

	/**
	 * Get the value from the given byte array using the specified size.
	 * 
	 * @param b array containing bytes
	 * @param size number of bytes to use from array at offset 0
	 * @param signed boolean flag indicating the value is signed
	 * @return {@link BigInteger} with value
	 * @throws IndexOutOfBoundsException if byte array size is
	 * less than size
	 */
	default BigInteger getBigInteger(byte[] b, int size, boolean signed) {
		return getBigInteger(b, 0, size, signed);
	}

	/**
	 * Get the value from the given byte array using the specified size.
	 * 
	 * @param b array containing bytes
	 * @param size number of bytes to use from array
	 * @param offset offset into byte array for getting the long
	 * @param signed boolean flag indicating the value is signed
	 * @return {@link BigInteger} with value
	 * @throws IndexOutOfBoundsException if byte array size is
	 * less than offset+size
	 */
	BigInteger getBigInteger(byte[] b, int offset, int size, boolean signed);

	//-------------------------------------------------------------------------------

	/**
	 * Converts the short value to an array of bytes.
	 * 
	 * @param value short value to be converted
	 * @return array of bytes
	 */
	default byte[] getBytes(short value) {
		byte[] bytes = new byte[2];
		getBytes(value, bytes);
		return bytes;
	}

	/**
	 * Converts the int value to an array of bytes.
	 * 
	 * @param value int value to be converted
	 * @return array of bytes
	 */
	default byte[] getBytes(int value) {
		byte[] bytes = new byte[4];
		getBytes(value, bytes);
		return bytes;
	}

	/**
	 * Converts the long value to an array of bytes.
	 * 
	 * @param value long value to be converted
	 * @return array of bytes
	 */
	default byte[] getBytes(long value) {
		byte[] bytes = new byte[8];
		getBytes(value, bytes);
		return bytes;
	}

	/**
	 * Converts the value to an array of bytes.
	 * 
	 * @param value value to be converted
	 * @param size value size in bytes
	 * @return array of bytes
	 */
	default byte[] getBytes(BigInteger value, int size) {
		byte[] bytes = new byte[size];
		putBigInteger(bytes, 0, size, value);
		return bytes;
	}

	//-------------------------------------------------------------------------------

	/**
	 * Writes a short value into a byte array.
	 * 
	 * @param b array to contain the bytes
	 * @param value the short value
	 * @throws IndexOutOfBoundsException if byte array is too small to hold the value
	 */
	default void putShort(byte[] b, short value) {
		putShort(b, 0, value);
	}

	/**
	 * Writes a short value into the byte array at the given offset
	 * 
	 * @param b array to contain the bytes
	 * @param offset the offset into the byte array to store the value
	 * @param value the short value
	 * @throws IndexOutOfBoundsException if offset is too large or byte array
	 * is too small to hold the value
	 */
	void putShort(byte[] b, int offset, short value);

	/**
	 * Writes a int value into a byte array.
	 * <p>
	 * See {@link #getBytes(int, byte[])}
	 * 
	 * @param b array to contain the bytes
	 * @param value the int value
	 * @throws IndexOutOfBoundsException if byte array is too small to hold the value
	 */
	default void putInt(byte[] b, int value) {
		putInt(b, 0, value);
	}

	/**
	 * Writes a int value into the byte array at the given offset.
	 * <p>
	 * See {@link #getBytes(int, byte[], int)}
	 * 
	 * @param b array to contain the bytes
	 * @param offset the offset into the byte array to store the value
	 * @param value the int value
	 * @throws IndexOutOfBoundsException if offset is too large or byte array
	 * is too small to hold the value
	 */
	void putInt(byte[] b, int offset, int value);

	/**
	 * Writes a long value into a byte array.
	 * <p>
	 * See {@link #getBytes(long, byte[])}
	 * 
	 * @param b array to contain the bytes
	 * @param value the long value
	 * @throws IndexOutOfBoundsException if byte array is too small to hold the value
	 */
	default void putLong(byte[] b, long value) {
		putLong(b, 0, value);
	}

	/**
	 * Writes a long value into the byte array at the given offset
	 * <p>
	 * See {@link #getBytes(long, byte[], int)}
	 * 
	 * @param b array to contain the bytes
	 * @param offset the offset into the byte array to store the value
	 * @param value the long value
	 * @throws IndexOutOfBoundsException if offset is too large or byte array
	 * is too small to hold the value
	 */
	default void putLong(byte[] b, int offset, long value) {
		putValue(value, Long.BYTES, b, offset);
	}

	/**
	 * Converts the given value to bytes using the number of least significant bytes
	 * specified by size.
	 * <p>
	 * 
	 * @param value value to convert to bytes
	 * @param size number of least significant bytes of value to be written to the byte array
	 * @param b byte array to store bytes
	 * @param offset offset into byte array to put the bytes
	 * @throws IndexOutOfBoundsException if (offset+size)&gt;b.length
	 */
	void putValue(long value, int size, byte[] b, int offset);

	/**
	 * Writes a value of specified size into the byte array at the given offset.
	 * <p>
	 * See {@link #getBytes(BigInteger, int, byte[], int)}
	 * 
	 * @param b array to contain the bytes at offset 0
	 * @param size number of bytes to be written
	 * @param value BigInteger value to convert 
	 * @throws IndexOutOfBoundsException if byte array is less than specified size
	 */
	default void putBigInteger(byte[] b, int size, BigInteger value) {
		putBigInteger(b, 0, size, value);
	}

	/**
	 * Writes a value of specified size into the byte array at the given offset
	 * <p>
	 * See {@link #getBytes(BigInteger, int, byte[], int)}
	 * 
	 * @param b array to contain the bytes
	 * @param offset the offset into the byte array to store the value
	 * @param size number of bytes to be written
	 * @param value BigInteger value to convert
	 * @throws IndexOutOfBoundsException if (offset+size)&gt;b.length
	 */
	public void putBigInteger(byte[] b, int offset, int size, BigInteger value);

	//--------------------------------------------------------------------------------

	/**
	 * Converts the given value to bytes.
	 * See {@link #putShort(byte[], short)}
	 * @param value value to convert to bytes
	 * @param b byte array to store bytes
	 * @throws IndexOutOfBoundsException if b.length is not at least
	 * 2.
	 */
	default void getBytes(short value, byte[] b) {
		getBytes(value, b, 0);
	}

	/**
	 * Converts the given value to bytes.
	 * <p>
	 * See {@link #putShort(byte[], int, short)}
	 * 
	 * @param value value to convert to bytes
	 * @param b byte array to store bytes
	 * @param offset offset into byte array to put the bytes
	 * @throws IndexOutOfBoundsException if (offset+2)&gt;b.length
	 */
	default void getBytes(short value, byte[] b, int offset) {
		putShort(b, offset, value);
	}

	/**
	 * Converts the given value to bytes.
	 * <p>
	 * See {@link #putInt(byte[], int)}
	 * 
	 * @param value value to convert to bytes
	 * @param b byte array to store bytes
	 * @throws IndexOutOfBoundsException if b.length is not at least
	 * 4.
	 */
	default void getBytes(int value, byte[] b) {
		getBytes(value, b, 0);
	}

	/**
	 * Converts the given value to bytes.
	 * <p>
	 * See {@link #putInt(byte[], int)}
	 * 
	 * @param value value to convert to bytes
	 * @param b byte array to store bytes
	 * @param offset offset into byte array to put the bytes
	 * @throws IndexOutOfBoundsException if (offset+4)&gt;b.length
	 */
	default void getBytes(int value, byte[] b, int offset) {
		putInt(b, offset, value);
	}

	/**
	 * Converts the given value to bytes.
	 * <p>
	 * See {@link #putLong(byte[], long)}
	 * 
	 * @param value value to convert to bytes
	 * @param b byte array to store bytes
	 * @throws IndexOutOfBoundsException if b.length is not at least
	 * 8.
	 */
	default void getBytes(long value, byte[] b) {
		getBytes(value, b, 0);
	}

	/**
	 * Converts the given value to bytes.
	 * <p>
	 * See {@link #putLong(byte[], long)}
	 * 
	 * @param value value to convert to bytes
	 * @param b byte array to store bytes
	 * @param offset offset into byte array to put the bytes
	 * @throws IndexOutOfBoundsException if (offset+8)&gt;b.length
	 */
	default void getBytes(long value, byte[] b, int offset) {
		putLong(b, offset, value);
	}

	/**
	 * Converts the given value to bytes using the number of least significant bytes
	 * specified by size.
	 * <p>
	 * See {@link #putValue(long, int, byte[], int)}
	 * 
	 * @param value value to convert to bytes
	 * @param size number of least significant bytes of value to be written to the byte array
	 * @param b byte array to store bytes
	 * @param offset offset into byte array to put the bytes
	 * @throws IndexOutOfBoundsException if (offset+size)&gt;b.length
	 */
	default void getBytes(long value, int size, byte[] b, int offset) {
		putValue(value, size, b, offset);
	}

	/**
	 * Converts the given value to bytes using the number of least significant bytes
	 * specified by size.
	 * <p>
	 * See {@link #putBigInteger(byte[], int, BigInteger)}
	 * 
	 * @param value value to convert to bytes
	 * @param size number of least significant bytes of value to be written to the byte array
	 * @param b byte array to store bytes
	 * @param offset offset into byte array to put the bytes
	 * @throws IndexOutOfBoundsException if (offset+size)&gt;b.length.
	 */
	default void getBytes(BigInteger value, int size, byte[] b, int offset) {
		putBigInteger(b, offset, size, value);
	}

	/**
	 * Swap the least-significant bytes (based upon size)
	 * @param val value whose bytes are to be swapped
	 * @param size number of least significant bytes to be swapped
	 * @return value with bytes swapped (any high-order bytes beyond size will be 0)
	 */
	public static long swapBytes(long val, int size) {
		long res = 0;
		while (size > 0) {
			res <<= 8;
			res |= (val & 0xff);
			val >>>= 8;
			size -= 1;
		}
		return res;
	}

}
