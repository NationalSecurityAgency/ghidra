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
import java.util.Arrays;

import db.buffers.DataBuffer;

/**
 * <code>BinaryField</code> provides a wrapper for variable length binary data which is read or
 * written to a Record. 
 */
public class BinaryField extends Field {

	/**
	 * Instance intended for defining a {@link Table} {@link Schema}
	 */
	public static final BinaryField INSTANCE = new BinaryField(null, true);

	protected byte[] data;
	private Integer hashcode;

	/**
	 * Construct a binary data field with an initial value of null.
	 */
	public BinaryField() {
	}

	/**
	 * Construct a binary data field with an initial value of data.
	 * @param data initial value
	 */
	public BinaryField(byte[] data) {
		this(data, false);
	}

	/**
	 * Construct a binary data field with an initial value of data.
	 * @param data initial value
	 * @param immutable true if field value is immutable
	 */
	BinaryField(byte[] data, boolean immutable) {
		super(immutable);
		this.data = data;
	}

	@Override
	boolean isNull() {
		return data == null;
	}

	@Override
	void setNull() {
		checkImmutable();
		data = null;
	}

	@Override
	void checkImmutable() {
		super.checkImmutable();
		hashcode = null;
	}

	@Override
	public byte[] getBinaryData() {
		return data;
	}

	@Override
	public void setBinaryData(byte[] data) {
		checkImmutable();
		this.data = data;
	}

	@Override
	int length() {
		return (data == null) ? 4 : (data.length + 4);
	}

	@Override
	int write(Buffer buf, int offset) throws IOException {
		if (data == null) {
			return buf.putInt(offset, -1);
		}
		offset = buf.putInt(offset, data.length);
		return buf.put(offset, data);
	}

	@Override
	int read(Buffer buf, int offset) throws IOException {
		checkImmutable();
		int len = buf.getInt(offset);
		offset += 4;
		if (len < 0) {
			data = null;
		}
		else {
			data = buf.get(offset, len);
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
		return BINARY_OBJ_TYPE;
	}

	@Override
	void truncate(int length) {
		checkImmutable();
		int maxLen = length - 4;
		if (data != null && data.length > maxLen) {
			byte[] newData = new byte[maxLen];
			System.arraycopy(data, 0, newData, 0, maxLen);
			data = newData;
		}
	}

	@Override
	public int compareTo(Field o) {
		BinaryField f = (BinaryField) o;
		if (data == null) {
			if (f.data == null) {
				return 0;
			}
			return -1;
		}
		else if (f.data == null) {
			return 1;
		}

		int len1 = data.length;
		int len2 = f.data.length;
		int offset1 = 0;
		int offset2 = 0;
		int n = Math.min(len1, len2);
		while (n-- != 0) {
			int b1 = data[offset1++] & 0xff;
			int b2 = f.data[offset2++] & 0xff;
			if (b1 != b2) {
				return b1 - b2;
			}
		}
		return len1 - len2;
	}

	@Override
	int compareTo(DataBuffer buffer, int offset) {
		int len = buffer.getInt(offset);
		if (data == null) {
			if (len < 0) {
				return 0;
			}
			return -1;
		}
		else if (len < 0) {
			return 1;
		}

		return -buffer.unsignedCompareTo(data, offset + 4, len);
	}

	@Override
	public BinaryField copyField() {
		return new BinaryField(getBinaryData().clone());
	}

	@Override
	public BinaryField newField() {
		return new BinaryField();
	}

	@Override
	BinaryField getMinValue() {
		throw new UnsupportedOperationException();
	}

	@Override
	BinaryField getMaxValue() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null || obj.getClass() != getClass()) {
			return false;
		}
		BinaryField f = (BinaryField) obj;
		return Arrays.equals(f.data, data);
	}

	@Override
	public int hashCode() {
		if (hashcode == null) {
			int h = 0;
			if (data != null) {
				for (byte b : data) {
					h = 31 * h + (b & 0xff);
				}
			}
			hashcode = h;
		}
		return hashcode;
	}

	/// Methods below should not use data field directly

	@Override
	public String toString() {
		String classname = getClass().getSimpleName();
		byte[] d = getBinaryData();
		if (d == null) {
			return classname + ": null";
		}
		return classname = "[" + d.length + "] = 0x" + getValueAsString(d);
	}

	@Override
	public String getValueAsString() {
		byte[] d = getBinaryData();
		if (d == null) {
			return "null";
		}
		return "{" + getValueAsString(d) + "}";
	}

	/**
	 * Get format value string for byte array
	 * @param data byte array
	 * @return formatted value string
	 */
	public static String getValueAsString(byte[] data) {
		StringBuffer buf = new StringBuffer();
		int i = 0;
		for (; i < 24 && i < data.length; i++) {
			String b = Integer.toHexString(data[i] & 0xff);
			if (b.length() == 1) {
				buf.append('0');
			}
			buf.append(b);
			buf.append(' ');
		}
		if (i < data.length) {
			buf.append("...");
		}
		return buf.toString();
	}

}
