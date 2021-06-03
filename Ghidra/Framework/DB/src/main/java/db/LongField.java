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
package db;

import java.io.IOException;

import db.buffers.DataBuffer;

/**
 * <code>LongField</code> provides a wrapper for 8-byte signed long data 
 * which is read or written to a Record. 
 */
public final class LongField extends Field {

	/**
	 * Minimum long field value
	 */
	public static final LongField MIN_VALUE = new LongField(Long.MIN_VALUE, true);

	/**
	 * Maximum long field value
	 */
	public static final LongField MAX_VALUE = new LongField(Long.MAX_VALUE, true);

	/**
	 * Zero long field value
	 */
	public static final LongField ZERO_VALUE = new LongField(0, true);

	/**
	 * Instance intended for defining a {@link Table} {@link Schema}
	 */
	public static final LongField INSTANCE = ZERO_VALUE;

	private long value;

	/**
	 * Construct a long field with an initial value of 0.
	 */
	public LongField() {
	}

	/**
	 * Construct a long field with an initial value of l.
	 * @param l initial value
	 */
	public LongField(long l) {
		this(l, false);
	}

	/**
	 * Construct a long field with an initial value of l.
	 * @param l initial value
	 * @param immutable true if field value is immutable
	 */
	LongField(long l, boolean immutable) {
		super(immutable);
		value = l;
	}

	@Override
	boolean isNull() {
		return value == 0;
	}

	@Override
	void setNull() {
		checkImmutable();
		value = 0;
	}

	@Override
	public long getLongValue() {
		return value;
	}

	@Override
	public void setLongValue(long value) {
		checkImmutable();
		this.value = value;
	}

	@Override
	int length() {
		return 8;
	}

	@Override
	int write(Buffer buf, int offset) throws IOException {
		return buf.putLong(offset, value);
	}

	@Override
	int read(Buffer buf, int offset) throws IOException {
		checkImmutable();
		value = buf.getLong(offset);
		return offset + 8;
	}

	@Override
	int readLength(Buffer buf, int offset) throws IOException {
		return 8;
	}

	@Override
	byte getFieldType() {
		return LONG_TYPE;
	}

	@Override
	public String toString() {
		return "LongField: " + Long.toString(value);
	}

	@Override
	public String getValueAsString() {
		return "0x" + Long.toHexString(value);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null || !(obj instanceof LongField)) {
			return false;
		}
		return ((LongField) obj).value == value;
	}

	@Override
	public int compareTo(Field o) {
		if (!(o instanceof LongField)) {
			throw new UnsupportedOperationException("may only compare similar Field types");
		}
		LongField f = (LongField) o;
		if (value == f.value) {
			return 0;
		}
		else if (value < f.value) {
			return -1;
		}
		return 1;
	}

	@Override
	int compareTo(DataBuffer buffer, int offset) {
		long otherValue = buffer.getLong(offset);
		if (value == otherValue) {
			return 0;
		}
		else if (value < otherValue) {
			return -1;
		}
		return 1;
	}

	@Override
	public LongField copyField() {
		return new LongField(getLongValue());
	}

	@Override
	public LongField newField() {
		return new LongField();
	}

	@Override
	public byte[] getBinaryData() {
		return new byte[] { (byte) (value >> 56), (byte) (value >> 48), (byte) (value >> 40),
			(byte) (value >> 32), (byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8),
			(byte) value };
	}

	@Override
	public void setBinaryData(byte[] bytes) {
		checkImmutable();
		if (bytes.length != 8) {
			throw new IllegalFieldAccessException();
		}
		value = (((long) bytes[0] & 0xff) << 56) | (((long) bytes[1] & 0xff) << 48) |
			(((long) bytes[2] & 0xff) << 40) | (((long) bytes[3] & 0xff) << 32) |
			(((long) bytes[4] & 0xff) << 24) | (((long) bytes[5] & 0xff) << 16) |
			(((long) bytes[6] & 0xff) << 8) | ((long) bytes[7] & 0xff);
	}

	@Override
	public int hashCode() {
		return (int) (value ^ (value >>> 32));
	}

	@Override
	LongField getMinValue() {
		return MIN_VALUE;
	}

	@Override
	LongField getMaxValue() {
		return MAX_VALUE;
	}

}
