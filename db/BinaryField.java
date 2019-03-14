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

import java.io.IOException;
import java.util.Arrays;

/**
 * <code>BinaryField</code> provides a wrapper for variable length binary data which is read or
 * written to a Record. 
 */
public class BinaryField extends Field {

	protected byte[] data;

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
		this.data = data;
	}

	/*
	 * @see ghidra.framework.store.db.Field#getBinaryData()
	 */
	@Override
	public byte[] getBinaryData() {
		return data;
	}

	/*
	 * @see ghidra.framework.store.db.Field#setBinaryData(byte[])
	 */
	@Override
	public void setBinaryData(byte[] data) {
		this.data = data;
	}

	/*
	 * @see ghidra.framework.store.db.Field#length()
	 */
	@Override
	int length() {
		return (data == null) ? 4 : (data.length + 4);
	}

	/*
	 * @see ghidra.framework.store.db.Field#write(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int write(Buffer buf, int offset) throws IOException {
		if (data == null) {
			return buf.putInt(offset, -1);
		}
		offset = buf.putInt(offset, data.length);
		return buf.put(offset, data);
	}

	/*
	 * @see ghidra.framework.store.db.Field#read(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int read(Buffer buf, int offset) throws IOException {
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
		return BINARY_OBJ_TYPE;
	}

	/*
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		if (data == null) {
			return "BinaryField: null";
		}
		return "BinaryField[" + data.length + "] = " + getValueAsString();
	}

	@Override
	public String getValueAsString() {
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

	/*
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null || !(obj instanceof BinaryField))
			return false;
		BinaryField f = (BinaryField) obj;
		return Arrays.equals(f.data, data);
	}

//	/**
//	 * Get first 8 bytes of data as long value.
//	 * First data byte corresponds to most significant byte
//	 * of long value so that proper sign is preserved.
//	 * If data is null, Long.MIN_VALUE is returned.
//	 * @see ghidra.framework.store.db.Field#getLongValue()
//	 */
//	public long getLongValue() {
//		long value = 0;
//		if (data == null) {
//			return Long.MIN_VALUE;
//		}
//		for (int i = 0; i < 8 && i < data.length; i++) {
//			value = (value << 8) | ((long)data[i] & 0x000000ff);
//		}
//		if (data.length < 8) {
//			value = value << (8 * (8 - data.length));
//		}
//		return value;
//	}

	/*
	 * @see ghidra.framework.store.db.Field#truncate(int)
	 */
	@Override
	void truncate(int length) {
		int maxLen = length - 4;
		if (data != null && data.length > maxLen) {
			byte[] newData = new byte[maxLen];
			System.arraycopy(data, 0, newData, 0, maxLen);
			data = newData;
		}
	}

	/*
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
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

	/*
	 * @see ghidra.framework.store.db.Field#newField(ghidra.framework.store.db.Field)
	 */
	@Override
	public Field newField(Field fieldValue) {
		return new BinaryField(fieldValue.getBinaryData());
	}

	/*
	 * @see ghidra.framework.store.db.Field#newField()
	 */
	@Override
	public Field newField() {
		return new BinaryField();
	}

	/*
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return data.hashCode();
	}

}
