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
 * <code>BooleanField</code> provides a wrapper for boolean data which is read or
 * written to a Record. 
 */
public class BooleanField extends Field {

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
		value = b ? (byte) 1 : (byte) 0;
	}

	/*
	 * @see ghidra.framework.store.db.Field#getBooleanValue()
	 */
	@Override
	public boolean getBooleanValue() {
		return (value == 0) ? false : true;
	}

	/*
	 * @see ghidra.framework.store.db.Field#setBooleanValue(boolean)
	 */
	@Override
	public void setBooleanValue(boolean b) {

		this.value = b ? (byte) 1 : (byte) 0;
	}

	/*
	 * @see ghidra.framework.store.db.Field#length()
	 */
	@Override
	int length() {
		return 1;
	}

	/*
	 * @see ghidra.framework.store.db.Field#write(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int write(Buffer buf, int offset) throws IOException {
		return buf.putByte(offset, value);
	}

	/*
	 * @see ghidra.framework.store.db.Field#read(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int read(Buffer buf, int offset) throws IOException {
		value = buf.getByte(offset);
		return offset + 1;
	}

	/*
	 * @see ghidra.framework.store.db.Field#readLength(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int readLength(Buffer buf, int offset) throws IOException {
		return 1;
	}

	/*
	 * @see ghidra.framework.store.db.Field#getFieldType()
	 */
	@Override
	protected byte getFieldType() {
		return BOOLEAN_TYPE;
	}

	/*
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "BooleanField: " + Boolean.toString(getBooleanValue());
	}

	@Override
	public String getValueAsString() {
		return Boolean.toString(getBooleanValue());
	}

	/*
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null || !(obj instanceof BooleanField))
			return false;
		BooleanField otherField = (BooleanField) obj;
		return otherField.value == value;
	}

	/*
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(Field o) {
		BooleanField f = (BooleanField) o;
		if (value == f.value)
			return 0;
		else if (value < f.value)
			return -1;
		return 1;
	}

	/*
	 * @see ghidra.framework.store.db.Field#newField(ghidra.framework.store.db.Field)
	 */
	@Override
	public Field newField(Field fieldValue) {
		if (fieldValue.isVariableLength())
			throw new AssertException();
		return new BooleanField(fieldValue.getLongValue() != 0);
	}

	/*
	 * @see ghidra.framework.store.db.Field#newField()
	 */
	@Override
	public Field newField() {
		return new BooleanField();
	}

	/*
	 * @see ghidra.framework.store.db.Field#getLongValue()
	 */
	@Override
	public long getLongValue() {
		return value;
	}

	/*
	 * @see ghidra.framework.store.db.Field#getBinaryData()
	 */
	@Override
	public byte[] getBinaryData() {
		return new byte[] { value };
	}

	@Override
	public int hashCode() {
		// TODO Auto-generated method stub
		return value;
	}

}
