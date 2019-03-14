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
 * <code>LongField</code> provides a wrapper for 8-byte signed long data 
 * which is read or written to a Record. 
 */
public class LongField extends Field {

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
		value = l;
	}

	/*
	 * @see ghidra.framework.store.db.Field#getLongValue()
	 */
	@Override
	public long getLongValue() {
		return value;
	}

	/*
	 * @see ghidra.framework.store.db.Field#setLongValue(long)
	 */
	@Override
	public void setLongValue(long value) {
		this.value = value;
	}

	/*
	 * @see ghidra.framework.store.db.Field#length()
	 */
	@Override
	int length() {
		return 8;
	}

	/*
	 * @see ghidra.framework.store.db.Field#write(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int write(Buffer buf, int offset) throws IOException {
		return buf.putLong(offset, value);
	}

	/*
	 * @see ghidra.framework.store.db.Field#read(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int read(Buffer buf, int offset) throws IOException {
		value = buf.getLong(offset);
		return offset + 8;
	}

	/*
	 * @see ghidra.framework.store.db.Field#readLength(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int readLength(Buffer buf, int offset) throws IOException {
		return 8;
	}

	/*
	 * @see ghidra.framework.store.db.Field#getFieldType()
	 */
	@Override
	protected byte getFieldType() {
		return LONG_TYPE;
	}

	/*
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "LongField: " + Long.toString(value);
	}

	@Override
	public String getValueAsString() {
		return Long.toHexString(value);
	}

	/*
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null || !(obj instanceof LongField))
			return false;
		return ((LongField) obj).value == value;
	}

	/*
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(Field o) {
		LongField f = (LongField) o;
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
		return new LongField(fieldValue.getLongValue());
	}

	/*
	 * @see ghidra.framework.store.db.Field#newField()
	 */
	@Override
	public Field newField() {
		return new LongField();
	}

	/*
	 * @see ghidra.framework.store.db.Field#getBinaryData()
	 */
	@Override
	public byte[] getBinaryData() {
		return new byte[] { (byte) (value >> 56), (byte) (value >> 48), (byte) (value >> 40),
			(byte) (value >> 32), (byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8),
			(byte) value };
	}

	/*
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return (int) (value ^ (value >>> 32));
	}

}
