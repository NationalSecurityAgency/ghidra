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
package db;

import ghidra.util.exception.AssertException;

import java.io.IOException;

/**
 * <code>IntField</code> provides a wrapper for 4-byte signed integer data 
 * which is read or written to a Record. 
 */
public class IntField extends Field {

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
		value = i;
	}

	/**
	 * @see db.Field#getIntValue()
	 */
	@Override
	public int getIntValue() {
		return value;
	}

	/**
	 * @see db.Field#setIntValue(int)
	 */
	@Override
	public void setIntValue(int value) {
		this.value = value;
	}

	/**
	 * @see db.Field#length()
	 */
	@Override
	int length() {
		return 4;
	}

	/**
	 * @see db.Field#write(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int write(Buffer buf, int offset) throws IOException {
		return buf.putInt(offset, value);
	}

	/**
	 * @see db.Field#read(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int read(Buffer buf, int offset) throws IOException {
		value = buf.getInt(offset);
		return offset + 4;
	}

	/**
	 * @see db.Field#readLength(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int readLength(Buffer buf, int offset) throws IOException {
		return 4;
	}

	/**
	 * @see db.Field#getFieldType()
	 */
	@Override
	protected byte getFieldType() {
		return INT_TYPE;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "IntField: " + Integer.toString(value);
	}

	@Override
	public String getValueAsString() {
		return Integer.toHexString(value);
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null || !(obj instanceof IntField))
			return false;
		return ((IntField) obj).value == value;
	}

	/**
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(Field o) {
		IntField f = (IntField) o;
		if (value == f.value)
			return 0;
		else if (value < f.value)
			return -1;
		return 1;
	}

	/**
	 * @see db.Field#newField(docking.widgets.fieldpanel.Field)
	 */
	@Override
	public Field newField(Field fieldValue) {
		if (fieldValue.isVariableLength())
			throw new AssertException();
		return new IntField((int) fieldValue.getLongValue());
	}

	/**
	 * @see db.Field#newField()
	 */
	@Override
	public Field newField() {
		return new IntField();
	}

	/**
	 * @see db.Field#getLongValue()
	 */
	@Override
	public long getLongValue() {
		return value;
	}

	/**
	 * @see db.Field#setLongValue(long)
	 */
	@Override
	public void setLongValue(long value) {
		this.value = (int) value;
	}

	/**
	 * @see db.Field#getBinaryData()
	 */
	@Override
	public byte[] getBinaryData() {
		return new byte[] { (byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8),
			(byte) value };
	}

	/**
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return value;
	}
}
