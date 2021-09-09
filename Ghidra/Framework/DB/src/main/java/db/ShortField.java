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
 * <code>ShortField</code> provides a wrapper for 2-byte signed short data 
 * which is read or written to a Record. 
 */
public final class ShortField extends PrimitiveField {

	/**
	 * Minimum short field value
	 */
	public static final ShortField MIN_VALUE = new ShortField(Short.MIN_VALUE, true);

	/**
	 * Maximum short field value
	 */
	public static final ShortField MAX_VALUE = new ShortField(Short.MAX_VALUE, true);

	/**
	 * Zero short field value
	 */
	public static final ShortField ZERO_VALUE = new ShortField((short) 0, true);

	/**
	 * Instance intended for defining a {@link Table} {@link Schema}
	 */
	public static final ShortField INSTANCE = ZERO_VALUE;

	private short value;

	/**
	 * Construct a short field with an initial value of 0.
	 */
	public ShortField() {
	}

	/**
	 * Construct a short field with an initial value of s.
	 * @param s initial value
	 */
	public ShortField(short s) {
		this(s, false);
	}

	/**
	 * Construct a short field with an initial value of s.
	 * @param s initial value
	 * @param immutable true if field value is immutable
	 */
	ShortField(short s, boolean immutable) {
		super(immutable);
		value = s;
	}

	@Override
	void setNull() {
		super.setNull();
		value = 0;
	}

	@Override
	public short getShortValue() {
		return value;
	}

	@Override
	public void setShortValue(short value) {
		updatingPrimitiveValue();
		this.value = value;
	}

	@Override
	int length() {
		return 2;
	}

	@Override
	int write(Buffer buf, int offset) throws IOException {
		return buf.putShort(offset, value);
	}

	@Override
	int read(Buffer buf, int offset) throws IOException {
		updatingPrimitiveValue();
		value = buf.getShort(offset);
		return offset + 2;
	}

	@Override
	int readLength(Buffer buf, int offset) throws IOException {
		return 2;
	}

	@Override
	byte getFieldType() {
		return SHORT_TYPE;
	}

	@Override
	public String getValueAsString() {
		return "0x" + Integer.toHexString(value & 0xffff);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof ShortField)) {
			return false;
		}
		return ((ShortField) obj).value == value;
	}

	@Override
	public int compareTo(Field o) {
		ShortField f = (ShortField) o;
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
		short otherValue = buffer.getShort(offset);
		if (value == otherValue) {
			return 0;
		}
		else if (value < otherValue) {
			return -1;
		}
		return 1;
	}

	@Override
	public ShortField copyField() {
		if (isNull()) {
			ShortField copy = new ShortField();
			copy.setNull();
			return copy;
		}
		return new ShortField((short) getLongValue());
	}

	@Override
	public ShortField newField() {
		return new ShortField();
	}

	@Override
	public long getLongValue() {
		return value;
	}

	@Override
	public void setLongValue(long value) {
		setShortValue((short) value);
	}

	@Override
	public byte[] getBinaryData() {
		return new byte[] { (byte) (value >> 8), (byte) value };
	}

	@Override
	public void setBinaryData(byte[] bytes) {
		if (bytes.length != 2) {
			throw new IllegalFieldAccessException();
		}
		updatingPrimitiveValue();
		value = (short) (((bytes[0] & 0xff) << 8) | (bytes[1] & 0xff));
	}

	@Override
	public int hashCode() {
		return value;
	}

	@Override
	ShortField getMinValue() {
		return MIN_VALUE;
	}

	@Override
	ShortField getMaxValue() {
		return MAX_VALUE;
	}

}
