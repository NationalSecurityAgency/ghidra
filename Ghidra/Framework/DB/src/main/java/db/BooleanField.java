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
 * <code>BooleanField</code> provides a wrapper for boolean data which is read or
 * written to a Record. 
 */
public final class BooleanField extends Field {

	/**
	 * Minimum boolean field value (FALSE)
	 */
	public static final BooleanField MIN_VALUE = new BooleanField(false, true);

	/**
	 * Maximum boolean field value (TRUE)
	 */
	public static final BooleanField MAX_VALUE = new BooleanField(true, true);

	/**
	 * Instance intended for defining a {@link Table} {@link Schema}
	 */
	public static final BooleanField INSTANCE = MIN_VALUE;

	private byte value;

	/**
	 * Construct a boolean data field with an initial value of false.
	 */
	public BooleanField() {
	}

	/**
	 * Construct a boolean data field with an initial value of b.
	 * @param b initial value
	 */
	public BooleanField(boolean b) {
		this(b, false);
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

	/**
	 * Construct a boolean data field with an initial value of b.
	 * @param b initial value
	 * @param immutable true if field value is immutable
	 */
	BooleanField(boolean b, boolean immutable) {
		super(immutable);
		value = b ? (byte) 1 : (byte) 0;
	}

	@Override
	public boolean getBooleanValue() {
		return (value == 0) ? false : true;
	}

	@Override
	public void setBooleanValue(boolean b) {
		checkImmutable();
		this.value = b ? (byte) 1 : (byte) 0;
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
		checkImmutable();
		value = buf.getByte(offset);
		return offset + 1;
	}

	@Override
	int readLength(Buffer buf, int offset) throws IOException {
		return 1;
	}

	@Override
	byte getFieldType() {
		return BOOLEAN_TYPE;
	}

	@Override
	public String toString() {
		return "BooleanField: " + Boolean.toString(getBooleanValue());
	}

	@Override
	public String getValueAsString() {
		return Boolean.toString(getBooleanValue());
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null || !(obj instanceof BooleanField)) {
			return false;
		}
		BooleanField otherField = (BooleanField) obj;
		return otherField.value == value;
	}

	@Override
	public int compareTo(Field o) {
		BooleanField f = (BooleanField) o;
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
	public BooleanField copyField() {
		return new BooleanField(getLongValue() != 0);
	}

	@Override
	public BooleanField newField() {
		return new BooleanField();
	}

	@Override
	public long getLongValue() {
		return value;
	}

	@Override
	public byte[] getBinaryData() {
		return new byte[] { value };
	}

	@Override
	public void setBinaryData(byte[] bytes) {
		checkImmutable();
		if (bytes.length != 1) {
			throw new IllegalFieldAccessException();
		}
		value = bytes[0];
	}

	@Override
	public int hashCode() {
		return value;
	}

	@Override
	BooleanField getMinValue() {
		return MIN_VALUE;
	}

	@Override
	BooleanField getMaxValue() {
		return MAX_VALUE;
	}

}
