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

import ghidra.util.exception.AssertException;

/**
 * <code>Record</code> provides a portable container for data
 * associated with a fixed schema.  
 * A record instance contains both a primary key and zero or more data fields.  
 */
public class DBRecord implements Comparable<DBRecord> {

	final Schema schema;

	private Field key;
	private Field[] fieldValues;

	private int length = -1;

	boolean dirty = false;

	/**
	 * Construct an empty record corresponding to the specified schema and record key
	 * @param schema record schema
	 * @param key record key
	 */
	DBRecord(Schema schema, Field key) {
		this.schema = schema;
		this.key = key;
		if (!schema.getKeyFieldType().isSameType(key)) {
			throw new IllegalArgumentException("key differs from schema key type");
		}
		Field[] schemaFields = schema.getFields();
		fieldValues = new Field[schemaFields.length];
		for (int colIndex = 0; colIndex < schemaFields.length; colIndex++) {
			try {
				fieldValues[colIndex] = schemaFields[colIndex].newField();
				if (schema.isSparseColumn(colIndex)) {
					// sparse column default to null state/value
					fieldValues[colIndex].setNull();
				}
			}
			catch (Exception e) {
				throw new AssertException(e);
			}
		}
	}

	protected void invalidateLength() {
		length = -1;
	}

	/**
	 * Set the primary key associated with this record.
	 * @param key primary key
	 */
	public void setKey(long key) {
		if (!(this.key instanceof LongField)) {
			throw new AssertException();
		}
		this.key = new LongField(key);
	}

	/**
	 * Set the primary key associated with this record.
	 * @param key primary key
	 */
	public void setKey(Field key) {
		if (!this.key.getClass().equals(key.getClass())) {
			throw new AssertException();
		}
		this.key = key;
	}

	/**
	 * Get the record primary key.
	 * @return primary key as long value.
	 */
	public long getKey() {
		return key.getLongValue();
	}

	/**
	 * Get the record primary key as a Field object.
	 * @return primary key as a field object.
	 */
	public Field getKeyField() {
		return key;
	}

	/**
	 * Determine if this record's schema is the same as another record's
	 * schema.  This check factors column count and column field types only.
	 * @param otherRec another record
	 * @return true if records schemas are the same
	 */
	public boolean hasSameSchema(DBRecord otherRec) {
		Field[] otherFieldValues = otherRec.fieldValues;
		if (fieldValues.length != otherFieldValues.length) {
			return false;
		}
		for (int i = 0; i < fieldValues.length; i++) {
			if (!fieldValues[i].getClass().equals(otherFieldValues[i].getClass())) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Determine if this record's schema is compatible with the specified schema.  
	 * This check factors column count and column field types only.
	 * Index and sparse column checks are not performed.
	 * @param otherSchema other schema
	 * @return true if records schemas are the same
	 */
	public boolean hasSameSchema(Schema otherSchema) {
		if (otherSchema == this.schema) {
			return true;
		}
		if (fieldValues.length != otherSchema.getFieldCount()) {
			return false;
		}
		if (!key.isSameType(otherSchema.getKeyFieldType())) {
			return false;
		}
		Field[] otherFields = otherSchema.getFields();
		for (int i = 0; i < fieldValues.length; i++) {
			if (!fieldValues[i].isSameType(otherFields[i])) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Get the number of columns contained within this record.
	 * @return number of field columns.
	 */
	public int getColumnCount() {
		return fieldValues.length;
	}

	/**
	 * Get a copy of the specified field value.
	 * @param columnIndex field index
	 * @return Field field value
	 */
	public Field getFieldValue(int columnIndex) {
		Field f = fieldValues[columnIndex];
		return f.copyField();
	}

	/**
	 * Set the field value for the specified field.
	 * @param colIndex field index
	 * @param value field value (null permitted for sparse column only)
	 */
	public void setField(int colIndex, Field value) {
		if (fieldValues[colIndex].getFieldType() != value.getFieldType()) {
			throw new IllegalArgumentException();
		}
		invalidateLength();
		fieldValues[colIndex] = value;
	}

	/**
	 * Get the specified field.  The object returned must not be
	 * modified.
	 * @param columnIndex field index
	 * @return Field
	 */
	Field getField(int columnIndex) {
		return fieldValues[columnIndex];
	}

	/**
	 * Get all fields. The objects returned must not be
	 * modified.
	 * @return array of field values.
	 */
	Field[] getFields() {
		return fieldValues;
	}

	/**
	 * Determine if the specified field equals the field associated with the
	 * specified columnIndex.
	 * @param columnIndex field index
	 * @param field field value to compare with
	 * @return true if the fields are equal, else false.
	 */
	public boolean fieldEquals(int columnIndex, Field field) {
		return fieldValues[columnIndex].equals(field);
	}

	/**
	 * Compare two field values.
	 * @param columnIndex the field index within this record
	 * @param value another field value to compared
	 * @return 0 if equals, a negative number if this record's field is less
	 * than the specified value, or a positive number if this record's field is
	 * greater than the specified value.
	 */
	public int compareFieldTo(int columnIndex, Field value) {
		return fieldValues[columnIndex].compareTo(value);
	}

	/**
	 * Obtain a copy of this record object.
	 * @return Record
	 */
	public DBRecord copy() {
		DBRecord r = schema.createRecord(key.copyField());
		for (int i = 0; i < fieldValues.length; i++) {
			r.setField(i, fieldValues[i].copyField());
		}
		return r;
	}

	/**
	 * Get the stored record length.
	 * This method is used to determine the space required to store the data 
	 * fields within this record when written to a standard Buffer.
	 * @return int stored record length
	 */
	public final int length() {
		if (length < 0) {
			length = computeLength();
		}
		return length;
	}

	/**
	 * Compute record storage length
	 * @return record storage length
	 */
	int computeLength() {
		int len = 0;
		for (Field fieldValue : fieldValues) {
			len += fieldValue.length();
		}
		return len;
	}

	/**
	 * Get the long value for the specified field.
	 * @param colIndex field index
	 * @return field value
	 * @throws IllegalFieldAccessException if field does support long data access
	 */
	public long getLongValue(int colIndex) {
		return fieldValues[colIndex].getLongValue();
	}

	/**
	 * Set the long value for the specified field.
	 * @param colIndex field index
	 * @param value field value
	 * @throws IllegalFieldAccessException if field does support long data access
	 */
	public void setLongValue(int colIndex, long value) {
		dirty = true;
		fieldValues[colIndex].setLongValue(value);
	}

	/**
	 * Get the integer value for the specified field.
	 * @param colIndex field index
	 * @return field value
	 * @throws IllegalFieldAccessException if field does support integer data access
	 */
	public int getIntValue(int colIndex) {
		return fieldValues[colIndex].getIntValue();
	}

	/**
	 * Set the integer value for the specified field.
	 * @param colIndex field index
	 * @param value field value
	 * @throws IllegalFieldAccessException if field does support integer data access
	 */
	public void setIntValue(int colIndex, int value) {
		dirty = true;
		fieldValues[colIndex].setIntValue(value);
	}

	/**
	 * Get the short value for the specified field.
	 * @param colIndex field index
	 * @return field value
	 * @throws IllegalFieldAccessException if field does support short data access
	 */
	public short getShortValue(int colIndex) {
		return fieldValues[colIndex].getShortValue();
	}

	/**
	 * Set the short value for the specified field.
	 * @param colIndex field index
	 * @param value field value
	 * @throws IllegalFieldAccessException if field does support short data access
	 */
	public void setShortValue(int colIndex, short value) {
		dirty = true;
		fieldValues[colIndex].setShortValue(value);
	}

	/**
	 * Get the byte value for the specified field.
	 * @param colIndex field index
	 * @return field value
	 * @throws IllegalFieldAccessException if field does support byte data access
	 */
	public byte getByteValue(int colIndex) {
		return fieldValues[colIndex].getByteValue();
	}

	/**
	 * Set the byte value for the specified field.
	 * @param colIndex field index
	 * @param value field value
	 * @throws IllegalFieldAccessException if field does support byte data access
	 */
	public void setByteValue(int colIndex, byte value) {
		dirty = true;
		fieldValues[colIndex].setByteValue(value);
	}

	/**
	 * Get the boolean value for the specified field.
	 * @param colIndex field index
	 * @return field value
	 * @throws IllegalFieldAccessException if field does support boolean data access
	 */
	public boolean getBooleanValue(int colIndex) {
		return fieldValues[colIndex].getBooleanValue();
	}

	/**
	 * Set the boolean value for the specified field.
	 * @param colIndex field index
	 * @param value field value
	 * @throws IllegalFieldAccessException if field does support boolean data access
	 */
	public void setBooleanValue(int colIndex, boolean value) {
		dirty = true;
		fieldValues[colIndex].setBooleanValue(value);
	}

	/**
	 * Get the binary data array for the specified field.
	 * @param colIndex field index
	 * @return field data
	 * @throws IllegalFieldAccessException if field does support binary data access
	 */
	public byte[] getBinaryData(int colIndex) {
		return fieldValues[colIndex].getBinaryData();
	}

	/**
	 * Set the binary data array for the specified field.
	 * @param colIndex field index
	 * @param bytes field value
	 * @throws IllegalFieldAccessException if field does support binary data access
	 * or incorrect number of bytes provided
	 */
	public void setBinaryData(int colIndex, byte[] bytes) {
		dirty = true;
		invalidateLength();
		fieldValues[colIndex].setBinaryData(bytes);
	}

	/**
	 * Get the string value for the specified field.
	 * @param colIndex field index
	 * @return field data
	 * @throws IllegalFieldAccessException if field does support string data access
	 */
	public String getString(int colIndex) {
		return fieldValues[colIndex].getString();
	}

	/**
	 * Set the string value for the specified field.
	 * @param colIndex field index
	 * @param str field value
	 * @throws IllegalFieldAccessException if field does support string data access
	 */
	public void setString(int colIndex, String str) {
		dirty = true;
		invalidateLength();
		fieldValues[colIndex].setString(str);
	}

	/**
	 * Write the record fields to the specified buffer and offset.
	 * @param buf data buffer
	 * @param offset buffer offset
	 * @throws IOException thrown if IO error occurs
	 */
	public void write(Buffer buf, int offset) throws IOException {
		for (Field fieldValue : fieldValues) {
			offset = fieldValue.write(buf, offset);
		}
		dirty = false;
	}

	/**
	 * Read the record field data from the specified buffer and offset
	 * @param buf data buffer
	 * @param offset buffer offset
	 * @throws IOException thrown if IO error occurs
	 */
	public void read(Buffer buf, int offset) throws IOException {
		for (Field fieldValue : fieldValues) {
			offset = fieldValue.read(buf, offset);
		}
		dirty = false;
	}

	/**
	 * Determine if data fields have been modified since the last write
	 * occurred.
	 * @return true if the field data has not been saved, else false.
	 */
	public boolean isDirty() {
		return dirty;
	}

	@Override
	public int hashCode() {
		return key.hashCode();
	}

	/**
	 * Compare the content of two Records for equality.
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof DBRecord)) {
			return false;
		}
		DBRecord rec = (DBRecord) obj;
		return key.equals(rec.key) && Arrays.equals(fieldValues, rec.fieldValues);
	}

	/**
	 * Compares the key associated with this record with the 
	 * key of another record (obj).
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(DBRecord otherRec) {
		return key.compareTo(otherRec.key);
	}

	@Override
	public String toString() {
		return "{key:" + key + "}";
	}

}
