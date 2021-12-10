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
import java.io.UnsupportedEncodingException;

import db.buffers.DataBuffer;
import ghidra.util.exception.AssertException;

/**
 * <code>StringField</code> provides a wrapper for variable length String data which is read or
 * written to a Record. Strings are always encoded as UTF-8.
 */
public final class StringField extends Field {

	/**
	 * Null string field value
	 */
	public static final StringField NULL_VALUE = new StringField(null, true);

	/**
	 * Instance intended for defining a {@link Table} {@link Schema}
	 */
	public static final StringField INSTANCE = NULL_VALUE;

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
	 * @param str initial string value or null
	 */
	public StringField(String str) {
		this(str, false);
	}

	/**
	 * Construct a String field with an initial value of s.
	 * @param str initial string value or null
	 * @param immutable true if field value is immutable
	 */
	StringField(String str, boolean immutable) {
		super(immutable);
		doSetString(str);
	}

	@Override
	public boolean isNull() {
		return bytes == null;
	}

	@Override
	void setNull() {
		checkImmutable();
		str = null;
		bytes = null;
	}

	@Override
	public String getString() {
		return str;
	}

	@Override
	public void setString(String str) {
		checkImmutable();
		doSetString(str);
	}

	private void doSetString(String str) {
		this.str = str;
		try {
			bytes = (str != null ? str.getBytes(ENCODING) : null);
		}
		catch (UnsupportedEncodingException e) {
			throw new AssertException(e);
		}
	}

	@Override
	int length() {
		return (bytes == null) ? 4 : (bytes.length + 4);
	}

	@Override
	int write(Buffer buf, int offset) throws IOException {
		if (bytes == null) {
			return buf.putInt(offset, -1);
		}
		offset = buf.putInt(offset, bytes.length);
		return buf.put(offset, bytes);
	}

	@Override
	int read(Buffer buf, int offset) throws IOException {
		checkImmutable();
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

	@Override
	int readLength(Buffer buf, int offset) throws IOException {
		int len = buf.getInt(offset);
		return (len < 0 ? 0 : len) + 4;
	}

	@Override
	public boolean isVariableLength() {
		return true;
	}

	@Override
	byte getFieldType() {
		return STRING_TYPE;
	}

	@Override
	public String toString() {
		return "StringField: " + str;
	}

	@Override
	public String getValueAsString() {
		if (str == null) {
			return "null";
		}
		return "\"" + str + "\"";
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof StringField)) {
			return false;
		}
		StringField f = (StringField) obj;
		if (str == null) {
			return (f.str == null);
		}
		return str.equals(f.str);
	}

	@Override
	public byte[] getBinaryData() {
		return bytes;
	}

	@Override
	public void setBinaryData(byte[] bytes) {
		checkImmutable();
		if (bytes == null) {
			str = null;
		}
		else {
			this.bytes = bytes;
			try {
				str = new String(bytes, ENCODING);
			}
			catch (UnsupportedEncodingException e) {
				throw new AssertException(e);
			}
		}
	}

	@Override
	void truncate(int length) {
		int maxLen = length - 4;
		if (str != null && str.length() > maxLen) {
			setString(str.substring(0, maxLen));
		}
	}

	@Override
	public int compareTo(Field o) {
		StringField f = (StringField) o;
		if (str == null) {
			if (f.str == null) {
				return 0;
			}
			return -1;
		}
		else if (f.str == null) {
			return 1;
		}
		return str.compareTo(f.str);
	}

	@Override
	int compareTo(DataBuffer buffer, int offset) {
		StringField f = new StringField();
		try {
			f.read(buffer, offset);
		}
		catch (IOException e) {
			throw new AssertException(e); // DataBuffer does not throw IOException
		}
		return compareTo(f);
	}

	@Override
	public StringField copyField() {
		return new StringField(str);
	}

	@Override
	public StringField newField() {
		return new StringField();
	}

	@Override
	public int hashCode() {
		return str.hashCode();
	}

	@Override
	StringField getMinValue() {
		throw new UnsupportedOperationException();
	}

	@Override
	StringField getMaxValue() {
		throw new UnsupportedOperationException();
	}

}
