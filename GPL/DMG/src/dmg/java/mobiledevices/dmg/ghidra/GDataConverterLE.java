/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.ghidra;

/**
 * 
 * Helper class to convert a byte array to a Java primitive in Little endian
 * order, and to convert a primitive to a byte array.
 */

public class GDataConverterLE implements GDataConverter {
	public static GDataConverterLE INSTANCE = new GDataConverterLE();
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Constructor for BigEndianDataConverter.
	 */
	public GDataConverterLE() {
	}

	/**
	 * @see GDataConverter#getShort(byte[])
	 */
	public final short getShort(byte[] b) {
		return getShort(b, 0);
	}

	/**
	 * @see GDataConverter#getShort(byte[], int)
	 */
	public short getShort(byte[] b, int offset) {
		return (short) (((b[offset + 1] & 0xff) << 8) | (b[offset] & 0xff));
	}

	/**
	 * @see GDataConverter#getInt(byte[])
	 */
	public final int getInt(byte[] b) {
		return getInt(b, 0);
	}

	/**
	 * @see GDataConverter#getInt(byte[], int)
	 */
	public int getInt(byte[] b, int offset) {
		int v = b[offset + 3];
		for (int i = 2; i >= 0; i--) {
			v = (v << 8) | (b[offset + i] & 0xff);
		}
		return v;
	}

	/**
	 * @see GDataConverter#getLong(byte[])
	 */
	public final long getLong(byte[] b) {
		return getLong(b, 0);
	}

	/**
	 * @see GDataConverter#getLong(byte[], int)
	 */
	public long getLong(byte[] b, int offset) {
		long v = b[offset + 7];
		for (int i = 6; i >= 0; i--) {
			v = (v << 8) | (b[offset + i] & 0xff);
		}
		return v;
	}

	/**
	 * @see ghidra.util.GDataConverter#getValue(byte[], int)
	 */
	public long getValue(byte[] b, int size) {
		return getValue(b, 0, size);
	}

	/**
	 * @see ghidra.util.GDataConverter#getValue(byte[], int, int)
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

	/**
	 * @see GDataConverter#getBytes(short, byte[])
	 */
	public final void getBytes(short value, byte[] b) {
		getBytes(value, b, 0);
	}

	/**
	 * @see GDataConverter#getBytes(short, byte[], int)
	 */
	public void getBytes(short value, byte[] b, int offset) {
		b[offset + 1] = (byte) (value >> 8);
		b[offset] = (byte) (value & 0xff);
	}

	/**
	 * @see GDataConverter#getBytes(int, byte[])
	 */
	public final void getBytes(int value, byte[] b) {
		getBytes(value, b, 0);
	}

	/**
	 * @see GDataConverter#getBytes(int, byte[], int)
	 */
	public void getBytes(int value, byte[] b, int offset) {
		b[offset] = (byte) (value);
		for (int i = 1; i < 4; i++) {
			value >>= 8;
			b[offset + i] = (byte) (value);
		}
	}

	/**
	 * @see GDataConverter#getBytes(long, byte[])
	 */
	public final void getBytes(long value, byte[] b) {
		getBytes(value, 8, b, 0);
	}

	/**
	 * @see GDataConverter#getBytes(long, byte[], int)
	 */
	public void getBytes(long value, byte[] b, int offset) {
		getBytes(value, 8, b, offset);
	}

	/**
	 * @see ghidra.util.GDataConverter#getBytes(long, int, byte[], int)
	 */
	public void getBytes(long value, int size, byte[] b, int offset) {
		for (int i = 0; i < size; i++) {
			b[offset + i] = (byte) value;
			value >>= 8;
		}
	}

	/**
	 * @see ghidra.util.GDataConverter#putInt(byte[], int, int)
	 */
	public final void putInt(byte[] b, int offset, int value) {
		getBytes(value, b, offset);
	}

	/**
	 * @see ghidra.util.GDataConverter#putInt(byte[], int)
	 */
	public final void putInt(byte[] b, int value) {
		getBytes(value, b);
	}

	/**
	 * @see ghidra.util.GDataConverter#putLong(byte[], int, long)
	 */
	public final void putLong(byte[] b, int offset, long value) {
		getBytes(value, b, offset);
	}

	/**
	 * @see ghidra.util.GDataConverter#putLong(byte[], long)
	 */
	public final void putLong(byte[] b, long value) {
		getBytes(value, b);
	}

	/**
	 * @see ghidra.util.GDataConverter#putShort(byte[], int, short)
	 */
	public final void putShort(byte[] b, int offset, short value) {
		getBytes(value, b, offset);
	}

	/**
	 * @see ghidra.util.GDataConverter#putShort(byte[], short)
	 */
	public final void putShort(byte[] b, short value) {
		getBytes(value, b);
	}

	/**
	 * @see ghidra.util.GDataConverter#getBytes(int)
	 */
	public byte[] getBytes(int value) {
		byte[] bytes = new byte[4];
		getBytes(value, bytes);
		return bytes;
	}

	/**
	 * @see ghidra.util.GDataConverter#getBytes(long)
	 */
	public byte[] getBytes(long value) {
		byte[] bytes = new byte[8];
		getBytes(value, bytes);
		return bytes;
	}

	/**
	 * @see ghidra.util.GDataConverter#getBytes(short)
	 */
	public byte[] getBytes(short value) {
		byte[] bytes = new byte[2];
		getBytes(value, bytes);
		return bytes;
	}

}
