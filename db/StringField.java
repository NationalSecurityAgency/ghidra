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
import java.io.UnsupportedEncodingException;

/**
 * <code>StringField</code> provides a wrapper for variable length String data which is read or
 * written to a Record. Strings are always encoded as UTF-8.
 */
public class StringField extends Field {

	private static String ENCODING = "UTF-8";

	private String str;
	private byte[] bytes;

	/**
	 * Construct a String field with an initial value of null.
	 */
	public StringField() {
	}

	/**
	 * Construct a String field with an initial value of s.
	 * @param s initial value
	 */
	public StringField(String s) {
		setString(s);
	}

	/*
	 * @see ghidra.framework.store.db.Field#getString()
	 */
	@Override
	public String getString() {
		return str;
	}

	/*
	 * @see ghidra.framework.store.db.Field#setString(java.lang.String)
	 */
	@Override
	public void setString(String str) {
		this.str = str;
		try {
			bytes = (str != null ? str.getBytes(ENCODING) : null);
		}
		catch (UnsupportedEncodingException e) {
			throw new AssertException();
		}
	}

	/*
	 * @see ghidra.framework.store.db.Field#length()
	 */
	@Override
	int length() {
		return (bytes == null) ? 4 : (bytes.length + 4);
	}

	/*
	 * @see ghidra.framework.store.db.Field#write(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int write(Buffer buf, int offset) throws IOException {
		if (bytes == null) {
			return buf.putInt(offset, -1);
		}
		offset = buf.putInt(offset, bytes.length);
		return buf.put(offset, bytes);
	}

	/*
	 * @see ghidra.framework.store.db.Field#read(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int read(Buffer buf, int offset) throws IOException {
		int len = buf.getInt(offset);
		offset += 4;
		if (len < 0) {
			str = null;
			bytes = null;
		}
		else {
			bytes = buf.get(offset, len);
			str = new String(bytes, ENCODING);
			offset += len;
		}
		return offset;
	}

	/*
	 * @see ghidra.framework.store.db.Field#readLength(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int readLength(Buffer buf, int offset) throws IOException {
		int len = buf.getInt(offset);
		return (len < 0 ? 0 : len) + 4;
	}

	/*
	 * @see ghidra.framework.store.db.Field#isVariableLength()
	 */
	@Override
	public boolean isVariableLength() {
		return true;
	}

	/*
	 * @see ghidra.framework.store.db.Field#getFieldType()
	 */
	@Override
	protected byte getFieldType() {
		return STRING_TYPE;
	}

	/*
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "StringField: " + str;
	}

	@Override
	public String getValueAsString() {
		return "\"" + str + "\"";
	}

//	/**
//	 * Get first 8 bytes of string as long value.
//	 * First string byte corresponds to most significant byte
//	 * of long value.
//	 * If string is null, Long.MIN_VALUE is returned.
//	 * @see ghidra.framework.store.db.Field#getLongValue()
//	 */
//	public long getLongValue() {
//		if (str == null)
//			return Long.MIN_VALUE;
//		long value = 0;
//		byte[] data;
//		try {
//			data = (str == null) ? new byte[0] : str.getBytes(Buffer.ASCII);
//		} catch (UnsupportedEncodingException e) {
//			throw new AssertException();
//		}
//		for (int i = 0; i < 8 && i < data.length; i++) {
//			value = (value << 8) | ((long)data[i] & 0x000000ff);
//		}
//		return value;
//	}

	/*
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null || !(obj instanceof StringField))
			return false;
		StringField f = (StringField) obj;
		if (str == null) {
			return (f.str == null);
		}
		return str.equals(f.str);
	}

	/*
	 * @see ghidra.framework.store.db.Field#getBinaryData()
	 */
	@Override
	public byte[] getBinaryData() {
		return bytes;
	}

	/*
	 * @see ghidra.framework.store.db.Field#setBinaryData(byte[])
	 */
	@Override
	public void setBinaryData(byte[] bytes) {
		if (bytes == null) {
			str = null;
		}
		else {
			this.bytes = bytes;
			try {
				str = new String(bytes, ENCODING);
			}
			catch (UnsupportedEncodingException e) {
				throw new AssertException();
			}
		}
	}

	/*
	 * @see ghidra.framework.store.db.Field#truncate(int)
	 */
	@Override
	void truncate(int length) {
		int maxLen = length - 4;
		if (str != null && str.length() > maxLen) {
			setString(str.substring(0, maxLen));
		}
	}

	/*
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(Field o) {
		StringField f = (StringField) o;
		if (str == null) {
			if (f.str == null)
				return 0;
			return -1;
		}
		else if (f.str == null) {
			return 1;
		}
		return str.compareTo(f.str);
	}

	/*
	 * @see ghidra.framework.store.db.Field#newField(ghidra.framework.store.db.Field)
	 */
	@Override
	public Field newField(Field fieldValue) {
		if (fieldValue instanceof StringField) {
			return new StringField(fieldValue.getString());
		}
		try {
			return new StringField(new String(fieldValue.getBinaryData(), ENCODING));
		}
		catch (UnsupportedEncodingException e) {
		}
		throw new AssertException();
	}

	/*
	 * @see ghidra.framework.store.db.Field#newField()
	 */
	@Override
	public Field newField() {
		return new StringField();
	}

	/*
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return str.hashCode();
	}

}
