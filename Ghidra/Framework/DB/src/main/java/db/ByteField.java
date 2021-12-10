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
 * <code>ByteField</code> provides a wrapper for single signed byte data 
 * which is read or written to a Record. 
 */
public final class ByteField extends PrimitiveField {

	/**
	 * Minimum byte field value 
	 */
	public static final ByteField MIN_VALUE = new ByteField(Byte.MIN_VALUE, true);

	/**
	 * Maximum byte field value
	 */
	public static final ByteField MAX_VALUE = new ByteField(Byte.MAX_VALUE, true);

	/**
	 * Zero byte field value
	 */
	public static final ByteField ZERO_VALUE = new ByteField((byte) 0, true);

	/**
	 * Instance intended for defining a {@link Table} {@link Schema}
	 */
	public static final ByteField INSTANCE = ZERO_VALUE;

	private byte value;

	/**
	 * Construct a byte field with an initial value of 0.
	 */
	public ByteField() {
	}

	/**
	 * Construct a byte field with an initial value of b.
	 * @param b initial value
	 */
	public ByteField(byte b) {
		this(b, false);
	}

	/**
	 * Construct a byte field with an initial value of b.
	 * @param b initial value
	 * @param immutable true if field value is immutable
	 */
	ByteField(byte b, boolean immutable) {
		super(immutable);
		value = b;
	}

	@Override
	void setNull() {
		super.setNull();
		value = 0;
	}

	@Override
	public byte getByteValue() {
		return value;
	}

	@Override
	public void setByteValue(byte value) {
		updatingPrimitiveValue();
		this.value = value;
	}

	@Override
	int length() {
		return 1;
	}

	@Override
	int write(Buffer buf, int offset) throws IOException {
		return buf.putByte(offset, value);
	}

	@Override
	int read(Buffer buf, int offset) throws IOException {
		updatingPrimitiveValue();
		value = buf.getByte(offset);
		return offset + 1;
	}

	@Override
	int readLength(Buffer buf, int offset) throws IOException {
		return 1;
	}

	@Override
	byte getFieldType() {
		return BYTE_TYPE;
	}

	@Override
	public String getValueAsString() {
		return "0x" + Integer.toHexString(value & 0xff);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof ByteField)) {
			return false;
		}
		return ((ByteField) obj).value == value;
	}

	@Override
	public int compareTo(Field o) {
		ByteField f = (ByteField) o;
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
		byte otherValue = buffer.getByte(offset);
		if (value == otherValue) {
			return 0;
		}
		else if (value < otherValue) {
			return -1;
		}
		return 1;
	}

	@Override
	public ByteField copyField() {
		if (isNull()) {
			ByteField copy = new ByteField();
			copy.setNull();
			return copy;
		}
		return new ByteField((byte) getLongValue());
	}

	@Override
	public ByteField newField() {
		return new ByteField();
	}

	@Override
	public long getLongValue() {
		return value;
	}

	@Override
	public void setLongValue(long value) {
		setByteValue((byte) value);
	}

	@Override
	public byte[] getBinaryData() {
		return new byte[] { value };
	}

	@Override
	public void setBinaryData(byte[] bytes) {
		if (bytes.length != 1) {
			throw new IllegalFieldAccessException();
		}
		updatingPrimitiveValue();
		value = bytes[0];
	}

	@Override
	public int hashCode() {
		return value;
	}

	@Override
	ByteField getMinValue() {
		return MIN_VALUE;
	}

	@Override
	ByteField getMaxValue() {
		return MAX_VALUE;
	}

}
