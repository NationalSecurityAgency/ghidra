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
 * <code>ShortField</code> provides a wrapper for 2-byte signed short data 
 * which is read or written to a Record. 
 */
public class ShortField extends Field {

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
		value = s;
	}

	/*
	 * @see ghidra.framework.store.db.Field#getShortValue()
	 */
	@Override
	public short getShortValue() {
		return value;
	}

	/*
	 * @see ghidra.framework.store.db.Field#setShortValue(short)
	 */
	@Override
	public void setShortValue(short value) {
		this.value = value;
	}

	/*
	 * @see ghidra.framework.store.db.Field#length()
	 */
	@Override
	int length() {
		return 2;
	}

	/*
	 * @see ghidra.framework.store.db.Field#write(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int write(Buffer buf, int offset) throws IOException {
		return buf.putShort(offset, value);
	}

	/*
	 * @see ghidra.framework.store.db.Field#read(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int read(Buffer buf, int offset) throws IOException {
		value = buf.getShort(offset);
		return offset + 2;
	}

	/*
	 * @see ghidra.framework.store.db.Field#readLength(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int readLength(Buffer buf, int offset) throws IOException {
		return 2;
	}

	/*
	 * @see ghidra.framework.store.db.Field#getFieldType()
	 */
	@Override
	protected byte getFieldType() {
		return SHORT_TYPE;
	}

	/*
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "ShortField: " + Short.toString(value);
	}

	@Override
	public String getValueAsString() {
		return Integer.toHexString(value);
	}

	/*
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null || !(obj instanceof ShortField))
			return false;
		return ((ShortField) obj).value == value;
	}

	/*
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(Field o) {
		ShortField f = (ShortField) o;
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
		return new ShortField((short) fieldValue.getLongValue());
	}

	/*
	 * @see ghidra.framework.store.db.Field#newField()
	 */
	@Override
	public Field newField() {
		return new ShortField();
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
		this.value = (short) value;
	}

	/*
	 * @see ghidra.framework.store.db.Field#getBinaryData()
	 */
	@Override
	public byte[] getBinaryData() {
		return new byte[] { (byte) (value >> 8), (byte) value };
	}

	/*
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return value;
	}

}
