/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.ghidra;

import java.io.Serializable;

/**
 * 
 * Defines methods to convert byte arrays to a specific primitive Java types,
 * and to populate byte arrays from primitive Java types.
 * 
 * 
 */
public interface GDataConverter extends Serializable {

	/**
	 * Get the short value from the given byte array.
	 * @param b array containing bytes
	 * @throws IndexOutOfBoundsException if byte array size is
	 * less than 2.
	 */
	public short getShort(byte[] b);

	/**
	 * Get the short value from the given byte array.
	 * @param b array containing bytes
	 * @param offset offset into byte array for getting the short
	 * @throws IndexOutOfBoundsException if byte array size is
	 * less than offset+2.
	 */
	public short getShort(byte[] b, int offset);

	/**
	 * Get the int value from the given byte array.
	 * @param b array containing bytes
	 * @throws IndexOutOfBoundsException if byte array size is
	 * less than 4.
	 */
	public int getInt(byte[] b);

	/**
	 * Get the int value from the given byte array.
	 * @param b array containing bytes
	 * @param offset offset into byte array for getting the int
	 * @throws IndexOutOfBoundsException if byte array size is
	 * less than offset+4.
	 */
	public int getInt(byte[] b, int offset);

	/**
	 * Get the long value from the given byte array.
	 * @param b array containing bytes
	 * @throws IndexOutOfBoundsException if byte array size is
	 * less than 8.
	 */
	public long getLong(byte[] b);

	/**
	 * Get the long value from the given byte array.
	 * @param b array containing bytes
	 * @param offset offset into byte array for getting the long
	 * @throws IndexOutOfBoundsException if byte array size is
	 * less than offset+8.
	 */
	public long getLong(byte[] b, int offset);

	/**
	 * Get the value from the given byte array using the specified size.
	 * @param b array containing bytes
	 * @param size number of bytes to use from array at offset 0
	 * @throws IndexOutOfBoundsException if byte array size is
	 * less than size.
	 */
	public long getValue(byte[] b, int size);

	/**
	 * Get the value from the given byte array using the specified size.
	 * @param b array containing bytes
	 * @param size number of bytes to use from array
	 * @param offset offset into byte array for getting the long
	 * @throws IndexOutOfBoundsException if byte array size is
	 * less than offset+size or size is greater than 8 (sizeof long).
	 */
	public long getValue(byte[] b, int offset, int size);

	/**
	 * Converts the given value to bytes.
	 * @param value value to convert to bytes
	 * @param b byte array to store bytes
	 * @throws IndexOutOfBoundsException if b.length is not at least
	 * 2.
	 */
	public void getBytes(short value, byte[] b);

	/**
	 * Converts the given value to bytes.
	 * @param value value to convert to bytes
	 * @param b byte array to store bytes
	 * @param offset offset into byte array to put the bytes
	 * @throws IndexOutOfBoundsException if (offset+2)>b.length
	 */
	public void getBytes(short value, byte[] b, int offset);

	/**
	 * Converts the given value to bytes.
	 * @param value value to convert to bytes
	 * @param b byte array to store bytes
	 * @throws IndexOutOfBoundsException if b.length is not at least
	 * 4.
	 */
	public void getBytes(int value, byte[] b);

	/**
	 * Converts the given value to bytes.
	 * @param value value to convert to bytes
	 * @param b byte array to store bytes
	 * @param offset offset into byte array to put the bytes
	 * @throws IndexOutOfBoundsException if (offset+4)>b.length
	 */
	public void getBytes(int value, byte[] b, int offset);

	/**
	 * Converts the given value to bytes.
	 * @param value value to convert to bytes
	 * @param b byte array to store bytes
	 * @throws IndexOutOfBoundsException if b.length is not at least
	 * 8.
	 */
	public void getBytes(long value, byte[] b);

	/**
	 * Converts the given value to bytes.
	 * @param value value to convert to bytes
	 * @param b byte array to store bytes
	 * @param offset offset into byte array to put the bytes
	 * @throws IndexOutOfBoundsException if (offset+8)>b.length
	 */
	public void getBytes(long value, byte[] b, int offset);

	/**
	 * Converts the given value to bytes using the number of least significant bytes
	 * specified by size.
	 * @param value value to convert to bytes
	 * @param size number of least significant bytes of value to be written to the byte array
	 * @param b byte array to store bytes
	 * @param offset offset into byte array to put the bytes
	 * @throws IndexOutOfBoundsException if (offset+size)>b.length.
	 */
	public void getBytes(long value, int size, byte[] b, int offset);

	/**
	 * Converts the short value to an array of bytes.
	 * @param value short value to be converted
	 * @return array of bytes
	 */
	public byte[] getBytes(short value);

	/**
	 * Converts the int value to an array of bytes.
	 * @param value int value to be converted
	 * @return array of bytes
	 */
	public byte[] getBytes(int value);

	/**
	 * Converts the long value to an array of bytes.
	 * @param value long value to be converted
	 * @return array of bytes
	 */
	public byte[] getBytes(long value);

	/**
	 * Writes a short value into a byte array.
	 * @param b array to contain the bytes;
	 * @param value the short value
	 */
	public void putShort(byte[] b, short value);

	/**
	 * Writes a short value into the byte array at the given offset
	 * @param b array to contain the bytes;
	 * @param offset the offset into the byte array to store the value.
	 * @param value the short value
	 */
	public void putShort(byte[] b, int offset, short value);

	/**
	 * Writes a int value into a byte array.
	 * @param b array to contain the bytes;
	 * @param value the int value
	 */
	public void putInt(byte[] b, int value);

	/**
	 * Writes a int value into the byte array at the given offset
	 * @param b array to contain the bytes;
	 * @param offset the offset into the byte array to store the value.
	 * @param value the int value
	 */
	public void putInt(byte[] b, int offset, int value);

	/**
	 * Writes a long value into a byte array.
	 * @param b array to contain the bytes;
	 * @param value the long value
	 */
	public void putLong(byte[] b, long value);

	/**
	 * Writes a long value into the byte array at the given offset
	 * @param b array to contain the bytes;
	 * @param offset the offset into the byte array to store the value.
	 * @param value the long value
	 */
	public void putLong(byte[] b, int offset, long value);

}
