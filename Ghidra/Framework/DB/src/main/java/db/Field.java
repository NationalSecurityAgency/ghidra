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

/**
 * <code>Field</code> is an abstract data wrapper for use with Records.
 */
public abstract class Field implements Comparable<Field> {

	/**
	 * Field type for ByteField
	 * @see db.ByteField
	 */
	static final byte BYTE_TYPE = 0;

	/**
	 * Field type for ShortField
	 * @see db.ShortField
	 */
	static final byte SHORT_TYPE = 1;

	/**
	 * Field type for IntField
	 * @see db.IntField
	 */
	static final byte INT_TYPE = 2;

	/**
	 * Field type for LongField
	 * @see db.LongField
	 */
	static final byte LONG_TYPE = 3;

	/**
	 * Field type for StringField
	 * @see db.StringField
	 */
	static final byte STRING_TYPE = 4;

	/**
	 * Field type for BinaryField
	 * @see db.BinaryField
	 */
	static final byte BINARY_OBJ_TYPE = 5;

	/**
	 * Field type for BooleanField
	 * @see db.BooleanField
	 */
	static final byte BOOLEAN_TYPE = 6;

	/**
	 * Field type flag mask used to isolate flag bits
	 */
	static final byte TYPE_FLAG_MASK = (byte) 0xC0;

	/**
	 * Field base type mask used to isolate base type
	 */
	static final byte BASE_TYPE_MASK = (byte) 0x3F;

	/**
	 * Field type flag bit shared by all Index type fields
	 */
	static final byte INDEX_TYPE_FLAG = (byte) 0x80;

	/**
	 * Get field as a long value.
	 * All fixed-length field objects must implement this method
	 * @return long value
	 * @throws IllegalFieldAccessException thrown if method is not supported by specific
	 * Field instance.
	 */
	public long getLongValue() {
		throw new IllegalFieldAccessException();
	}

	/**
	 * Set field's long value.
	 * All fixed-length field objects must implement this method
	 * @param value long value
	 * @throws IllegalFieldAccessException thrown if method is not supported by specific
	 * Field instance.
	 */
	public void setLongValue(long value) {
		throw new IllegalFieldAccessException();
	}

	/**
	 * Get field as an integer value.
	 * @return integer value
	 * @throws IllegalFieldAccessException thrown if method is not supported by specific
	 * Field instance.
	 */
	public int getIntValue() {
		throw new IllegalFieldAccessException();
	}

	/**
	 * Set field's integer value.
	 * @param value integer value
	 * @throws IllegalFieldAccessException thrown if method is not supported by specific
	 * Field instance.
	 */
	public void setIntValue(int value) {
		throw new IllegalFieldAccessException();
	}

	/**
	 * Get field as a short value.
	 * @return short value
	 * @throws IllegalFieldAccessException thrown if method is not supported by specific
	 * Field instance.
	 */
	public short getShortValue() {
		throw new IllegalFieldAccessException();
	}

	/**
	 * Set field's short value.
	 * @param value short value
	 * @throws IllegalFieldAccessException thrown if method is not supported by specific
	 * Field instance.
	 */
	public void setShortValue(short value) {
		throw new IllegalFieldAccessException();
	}

	/**
	 * Get field as a byte value.
	 * @return byte value
	 * @throws IllegalFieldAccessException thrown if method is not supported by specific
	 * Field instance.
	 */
	public byte getByteValue() {
		throw new IllegalFieldAccessException();
	}

	/**
	 * Set field's byte value.
	 * @param value byte value
	 * @throws IllegalFieldAccessException thrown if method is not supported by specific
	 * Field instance.
	 */
	public void setByteValue(byte value) {
		throw new IllegalFieldAccessException();
	}

	/**
	 * Get field as a boolean value.
	 * @return boolean value
	 * @throws IllegalFieldAccessException thrown if method is not supported by specific
	 * Field instance.
	 */
	public boolean getBooleanValue() {
		throw new IllegalFieldAccessException();
	}

	/**
	 * Set field's boolean value.
	 * @param value boolean value
	 * @throws IllegalFieldAccessException thrown if method is not supported by specific
	 * Field instance.
	 */
	public void setBooleanValue(boolean value) {
		throw new IllegalFieldAccessException();
	}

	/**
	 * Get data as a byte array.
	 * @return byte[]
	 */
	abstract public byte[] getBinaryData();

	/**
	 * Set data from binary byte array.
	 * All variable-length fields must implement this method.
	 * @param bytes field data
	 */
	public void setBinaryData(byte[] bytes) {
		throw new IllegalFieldAccessException();
	}

	/**
	 * Get field as a String value.
	 * @return String value
	 * @throws IllegalFieldAccessException thrown if method is not supported by specific
	 * Field instance.
	 */
	public String getString() {
		throw new IllegalFieldAccessException();
	}

	/**
	 * Set field's String value.
	 * @param str String value
	 * @throws IllegalFieldAccessException thrown if method is not supported by specific
	 * Field instance.
	 */
	public void setString(String str) {
		throw new IllegalFieldAccessException();
	}

	/**
	 * Truncate a variable length field to the specified length.
	 * If current length is shorterm, this method has no affect.
	 * @param length 
	 */
	void truncate(int length) {
		throw new IllegalFieldAccessException();
	}

	/**
	 * @return true if a Field instance is variable length, else false.
	 */
	public boolean isVariableLength() {
		return false;
	}

	/**
	 * Create new instance of this field type.
	 * @param fieldValue initial field value.
	 * @return long
	 */
	public abstract Field newField(Field fieldValue);

	/**
	 * Create new instance of this field type.
	 * @return long
	 */
	public abstract Field newField();

	/**
	 * Return Field instance type as an integer value
	 */
	protected abstract byte getFieldType();

	/**
	 * Write the field to buf at the specified offset.  When writing variable length 
	 * fields, the length preceeds the actual data. 
	 * @param buf data buffer
	 * @param offset data offset
	 * @return next available Field offset within buffer, or -1 if end of buffer reached.
	 * @throws IOException thrown if IO error occurs
	 */
	abstract int write(Buffer buf, int offset) throws IOException;

	/**
	 * Read the field value from buf at the specified offset. When reading variable length 
	 * fields, the length preceeds the actual data. 
	 * @param buf data buffer
	 * @param offset data offset
	 * @return next Field offset within buffer, or -1 if end of buffer reached.
	 * @throws IOException thrown if IO error occurs
	 */
	abstract int read(Buffer buf, int offset) throws IOException;

	/**
	 * Get the total number of bytes which will be read from the buffer
	 * for this field.  For variable-length fields, only the length 
	 * portion of the data is examined within the buffer.  This method is intended
	 * to be used instead of the read method when only interested in the data 
	 * length.
	 * @param buf data buffer
	 * @param offset data offset
	 * @return total number of bytes for this field stored within buf
	 * @throws IOException thrown if IO error occurs
	 */
	abstract int readLength(Buffer buf, int offset) throws IOException;

	/**
	 * Get the number of bytes required to store this field value.
	 * For a variable length fields, this value also accounts for a 4-byte
	 * length prefix.  Additionally, this method should not be invoked when 
	 * working with stored data until after the read method has been invoked.
	 * @return total storage length
	 */
	abstract int length();

	/*
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public abstract boolean equals(Object obj);

	@Override
	public abstract int hashCode();

	public abstract String getValueAsString();

	/**
	 * Get the field associated with the specified type value.
	 * @param fieldType encoded Field type
	 * @return Field
	 * @throws UnsupportedFieldException if unsupported fieldType specified
	 */
	static Field getField(byte fieldType) throws UnsupportedFieldException {
		if ((fieldType & INDEX_TYPE_FLAG) == 0) {
			switch (fieldType & BASE_TYPE_MASK) {
				case LONG_TYPE:
					return new LongField();
				case INT_TYPE:
					return new IntField();
				case STRING_TYPE:
					return new StringField();
				case SHORT_TYPE:
					return new ShortField();
				case BYTE_TYPE:
					return new ByteField();
				case BOOLEAN_TYPE:
					return new BooleanField();
				case BINARY_OBJ_TYPE:
					return new BinaryField();
			}
		}
		else {
			return IndexField.getIndexField(fieldType);
		}
		throw new UnsupportedFieldException(fieldType);
	}

	public static class UnsupportedFieldException extends IOException {
		UnsupportedFieldException(byte fieldType) {
			super("Unsupported DB field type: 0x" + Integer.toHexString(fieldType & 0xff));
		}
	}

}
