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
 * <code>IntField</code> provides a wrapper for 4-byte signed integer data 
 * which is read or written to a Record. 
 */
public final class IntField extends Field {

	/**
	 * Minimum integer field value
	 */
	public static final IntField MIN_VALUE = new IntField(Integer.MIN_VALUE, true);

	/**
	 * Maximum integer field value
	 */
	public static final IntField MAX_VALUE = new IntField(Integer.MAX_VALUE, true);

	/**
	 * Zero int field value
	 */
	public static final IntField ZERO_VALUE = new IntField(0, true);

	/**
	 * Instance intended for defining a {@link Table} {@link Schema}
	 */
	public static final IntField INSTANCE = ZERO_VALUE;

	private int value;

	/**
	 * Construct an integer field with an initial value of 0.
	 */
	public IntField() {
	}

	/**
	 * Construct an integer field with an initial value of i.
	 * @param i initial value
	 */
	public IntField(int i) {
		this(i, false);
	}

	/**
	 * Construct an integer field with an initial value of i.
	 * @param i initial value
	 * @param immutable true if field value is immutable
	 */
	IntField(int i, boolean immutable) {
		super(immutable);
		value = i;
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
	public int getIntValue() {
		return value;
	}

	@Override
	public void setIntValue(int value) {
		checkImmutable();
		this.value = value;
	}

	@Override
	int length() {
		return 4;
	}

	@Override
	int write(Buffer buf, int offset) throws IOException {
		return buf.putInt(offset, value);
	}

	@Override
	int read(Buffer buf, int offset) throws IOException {
		checkImmutable();
		value = buf.getInt(offset);
		return offset + 4;
	}

	@Override
	int readLength(Buffer buf, int offset) throws IOException {
		return 4;
	}

	@Override
	byte getFieldType() {
		return INT_TYPE;
	}

	@Override
	public String toString() {
		return "IntField: " + Integer.toString(value);
	}

	@Override
	public String getValueAsString() {
		return "0x" + Integer.toHexString(value);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null || !(obj instanceof IntField)) {
			return false;
		}
		return ((IntField) obj).value == value;
	}

	@Override
	public int compareTo(Field o) {
		IntField f = (IntField) o;
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
		int otherValue = buffer.getInt(offset);
		if (value == otherValue) {
			return 0;
		}
		else if (value < otherValue) {
			return -1;
		}
		return 1;
	}

	@Override
	public IntField copyField() {
		return new IntField((int) getLongValue());
	}

	@Override
	public IntField newField() {
		return new IntField();
	}

	@Override
	public long getLongValue() {
		return value;
	}

	@Override
	public void setLongValue(long value) {
		setIntValue((int) value);
	}

	@Override
	public byte[] getBinaryData() {
		return new byte[] { (byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8),
			(byte) value };
	}

	@Override
	public void setBinaryData(byte[] bytes) {
		checkImmutable();
		if (bytes.length != 4) {
			throw new IllegalFieldAccessException();
		}
		value = ((bytes[0] & 0xff) << 24) | ((bytes[1] & 0xff) << 16) | ((bytes[2] & 0xff) << 8) |
			(bytes[3] & 0xff);
	}

	@Override
	public int hashCode() {
		return value;
	}

	@Override
	IntField getMinValue() {
		return MIN_VALUE;
	}

	@Override
	IntField getMaxValue() {
		return MAX_VALUE;
	}
}
