/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.ghidra;

/**
 * Helper class to convert a byte array to Java primitives and primitives to a
 * byte array in Big endian.
 * 
 * 
 * 
 */
public class GDataConverterBE implements GDataConverter {
	public static final GDataConverterBE INSTANCE = new GDataConverterBE();

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Constructor for BigEndianDataConverter.
	 */
	public GDataConverterBE() {
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
		return (short) (((b[offset] & 0xff) << 8) | (b[offset + 1] & 0xff));
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
		int v = b[offset];
		for (int i = 1; i < 4; i++) {
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
		long v = b[offset];
		for (int i = 1; i < 8; i++) {
			v = (v << 8) | (b[offset + i] & 0xff);
		}
		return v;
	}

	/**
	 * @see GDataConverter.util.DataConverter#getValue(byte[], int)
	 */
	public long getValue(byte[] b, int size) {
		return getValue(b, 0, size);
	}

	/**
	 * @see GDataConverter.util.DataConverter#getValue(byte[], int, int)
	 */
	public long getValue(byte[] b, int offset, int size) {
		if (size > 8) {
			throw new IndexOutOfBoundsException("size exceeds sizeof long: " + size);
		}
		long val = 0;
		for (int i = 0; i < size; i++) {
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
		b[offset] = (byte) (value >> 8);
		b[offset + 1] = (byte) (value & 0xff);
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
		b[offset + 3] = (byte) (value);
		for (int i = 2; i >= 0; i--) {
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
	 * @see GDataConverter.util.DataConverter#getBytes(long, int, byte[], int)
	 */
	public void getBytes(long value, int size, byte[] b, int offset) {
		for (int i = size - 1; i >= 0; i--) {
			b[offset + i] = (byte) value;
			value >>= 8;
		}
	}

	/**
	 * @see GDataConverter.util.DataConverter#putInt(byte[], int, int)
	 */
	public final void putInt(byte[] b, int offset, int value) {
		getBytes(value, b, offset);
	}

	/**
	 * @see GDataConverter.util.DataConverter#putInt(byte[], int)
	 */
	public final void putInt(byte[] b, int value) {
		getBytes(value, b);
	}

	/**
	 * @see GDataConverter.util.DataConverter#putLong(byte[], int, long)
	 */
	public final void putLong(byte[] b, int offset, long value) {
		getBytes(value, b, offset);
	}

	/**
	 * @see GDataConverter.util.DataConverter#putLong(byte[], long)
	 */
	public final void putLong(byte[] b, long value) {
		getBytes(value, b);
	}

	/**
	 * @see GDataConverter.util.DataConverter#putShort(byte[], int, short)
	 */
	public final void putShort(byte[] b, int offset, short value) {
		getBytes(value, b, offset);
	}

	/**
	 * @see GDataConverter.util.DataConverter#putShort(byte[], short)
	 */
	public final void putShort(byte[] b, short value) {
		getBytes(value, b);
	}

	/**
	 * @see GDataConverter.util.DataConverter#getBytes(int)
	 */
	public byte[] getBytes(int value) {
		byte[] bytes = new byte[4];
		getBytes(value, bytes);
		return bytes;
	}

	/**
	 * @see GDataConverter.util.DataConverter#getBytes(long)
	 */
	public byte[] getBytes(long value) {
		byte[] bytes = new byte[8];
		getBytes(value, bytes);
		return bytes;
	}

	/**
	 * @see GDataConverter.util.DataConverter#getBytes(short)
	 */
	public byte[] getBytes(short value) {
		byte[] bytes = new byte[2];
		getBytes(value, bytes);
		return bytes;
	}

}
