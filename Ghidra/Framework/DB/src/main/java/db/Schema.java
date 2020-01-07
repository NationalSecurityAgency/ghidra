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

import java.util.ArrayList;
import java.util.StringTokenizer;

import db.Field.UnsupportedFieldException;
import ghidra.util.exception.AssertException;

/**
 * Class for definining the columns in a Ghidra Database table.
 */
public class Schema {

	private static final String NAME_SEPARATOR = ";";

	private int version;

	private Field keyType;
	private String keyName;

	private Class<?>[] fieldClasses;
	private String[] fieldNames;

	private boolean isVariableLength;
	private int fixedLength;

	/**
	 * Construct a new Schema.
	 * @param version
	 * @param keyFieldClass Field class associated with primary key.  If the 
	 * class is LongField, the long key methods on Table must be used.  Specifying any 
	 * other Field class requires the use of the Field key methods on Table.
	 * @param keyName
	 * @param fieldClasses
	 * @param fieldNames
	 */
	public Schema(int version, Class<? extends Field> keyFieldClass, String keyName,
			Class<?>[] fieldClasses, String[] fieldNames) {
		this.version = version;
		this.keyType = getField(keyFieldClass);
		this.keyName = keyName;
		this.fieldClasses = new Class<?>[fieldClasses.length];
		this.fieldNames = fieldNames;
		if (fieldClasses.length != fieldNames.length)
			throw new IllegalArgumentException();
		isVariableLength = false;
		fixedLength = 0;
		for (int i = 0; i < fieldClasses.length; i++) {
			this.fieldClasses[i] = fieldClasses[i];
			Field field = getField(fieldClasses[i]);
			if (field.isVariableLength()) {
				isVariableLength = true;
			}
			fixedLength += field.length();
			if (fieldNames[i].indexOf(NAME_SEPARATOR) >= 0)
				throw new IllegalArgumentException();
		}
		if (isVariableLength) {
			fixedLength = 0;
		}
	}

	/**
	 * Construct a new Schema which uses a long key.  The Field key methods on Table
	 * should not be used.
	 * @param version
	 * @param keyName
	 * @param fieldClasses
	 * @param fieldNames
	 */
	public Schema(int version, String keyName, Class<?>[] fieldClasses, String[] fieldNames) {
		this(version, LongField.class, keyName, fieldClasses, fieldNames);
	}

	/**
	 * Construct a new Schema with the given number of columns
	 * @param version
	 * @param fieldTypes
	 * @param packedFieldNames packed list of field names separated by ';'.
	 * The first field name corresponds to the key name.
	 * @throws UnsupportedFieldException if unsupported fieldType specified
	 */
	Schema(int version, byte keyFieldType, byte[] fieldTypes, String packedFieldNames)
			throws UnsupportedFieldException {
		this.version = version;
		this.keyType = Field.getField(keyFieldType);
		parseNames(packedFieldNames);
		if (fieldTypes.length != fieldNames.length)
			throw new IllegalArgumentException();
		this.fieldClasses = new Class[fieldTypes.length];
		isVariableLength = false;
		fixedLength = 0;
		for (int i = 0; i < fieldTypes.length; i++) {
			Field field = Field.getField(fieldTypes[i]);
			fieldClasses[i] = field.getClass();
			if (field.isVariableLength()) {
				isVariableLength = true;
			}
			fixedLength += field.length();
		}
		if (isVariableLength) {
			fixedLength = 0;
		}
	}

	/**
	 * Determine if this schema can use LongKeyNode's within a table.
	 * @return true if LongKeyNode's can be used to store records produced with this schema.
	 */
	boolean useLongKeyNodes() {
		return keyType instanceof LongField;
	}

	/**
	 * Get the key Field class
	 * @return key Field classes
	 */
	public Class<? extends Field> getKeyFieldClass() {
		return keyType.getClass();
	}

	/**
	 * Get the Field type for the key.
	 * @return key Field type
	 */
	Field getKeyFieldType() {
		return keyType;
	}

	/**
	 * Get the key name
	 * @return key name
	 */
	public String getKeyName() {
		return keyName;
	}

	/**
	 * Get the list of data Field classes for this schema.
	 * The returned list is ordered consistent with the schema definition.
	 * @return data Field classes
	 */
	public Class<?>[] getFieldClasses() {
		return fieldClasses;
	}

	/**
	 * Get the list of data Field names for this schema.
	 * The returned list is ordered consistent with the schema definition.
	 * @return data Field names
	 */
	public String[] getFieldNames() {
		return fieldNames;
	}

	/**
	 * Get the number of data Fields
	 * @return data Field count
	 */
	public int getFieldCount() {
		return fieldClasses.length;
	}

	/**
	 * Parse the packed list of data Field names.
	 * The fieldNames array is initialized with the individual Field names.
	 * @param packedNames packed name list produced by the getPackedFieldNames() method.
	 */
	private void parseNames(String packedNames) {
		ArrayList<String> nameList = new ArrayList<String>();
		StringTokenizer st = new StringTokenizer(packedNames, NAME_SEPARATOR);
		while (st.hasMoreElements()) {
			nameList.add(st.nextToken());
		}
		keyName = nameList.remove(0);
		fieldNames = new String[nameList.size()];
		nameList.toArray(fieldNames);
	}

	/**
	 * Get the packed list of data Field names.
	 * @return packed name list.
	 */
	String getPackedFieldNames() {
		StringBuffer buf = new StringBuffer();
		buf.append(keyName);
		buf.append(NAME_SEPARATOR);
		for (int i = 0; i < fieldNames.length; i++) {
			buf.append(fieldNames[i]);
			buf.append(NAME_SEPARATOR);
		}
		return buf.toString();
	}

	/**
	 * Get the schema field types as a byte array.
	 * @return byte[] field type list
	 */
	byte[] getFieldTypes() {
		byte[] fieldTypes = new byte[fieldClasses.length];
		for (int i = 0; i < fieldClasses.length; i++) {
			fieldTypes[i] = getField(fieldClasses[i]).getFieldType();
		}
		return fieldTypes;
	}

	/**
	 * Get the schema version.
	 * @return schema version
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * Returns true if records for this Schema can be of variable lengths. 
	 * @return true if records with this Schema are variable length. 
	 */
	public boolean isVariableLength() {
		return isVariableLength;
	}

	/**
	 * Get length of fixed-length schema record.
	 * @return record length or 0 for variable length.
	 */
	public int getFixedLength() {
		return fixedLength;
	}

	/**
	 * Create an empty record for the specified key.
	 * @param key
	 * @return Record
	 */
	public Record createRecord(long key) {
		return createRecord(new LongField(key));
	}

	/**
	 * Create an empty record for the specified key.
	 * @param key
	 * @return new record
	 */
	public Record createRecord(Field key) {
		if (!getKeyFieldClass().equals(key.getClass())) {
			throw new IllegalArgumentException(
				"expected key field type of " + keyType.getClass().getSimpleName());
		}
		Field[] fieldValues = new Field[fieldClasses.length];
		for (int i = 0; i < fieldClasses.length; i++) {
			try {
				fieldValues[i] = (Field) fieldClasses[i].newInstance();
			}
			catch (Exception e) {
				throw new AssertException();
			}
		}
		return new Record(key, fieldValues);
	}

	/**
	 * Get a new instance of a data Field object for the specified column.
	 * @param colIndex field index
	 * @return new Field object suitable for data reading/writing.
	 */
	Field getField(int colIndex) {
		try {
			return (Field) fieldClasses[colIndex].newInstance();
		}
		catch (Exception e) {
			throw new AssertException(e.getMessage());
		}
	}

	/**
	 * Get a new instance of a data Field object for the specified Field class.
	 * @param fieldClass Field implementation class
	 * @return new Field object suitable for data reading/writing.
	 */
	private Field getField(Class<?> fieldClass) {
		try {
			return (Field) fieldClass.newInstance();
		}
		catch (Exception e) {
			throw new AssertException(e.getMessage());
		}
	}

	/**
	 * Compare two schemas for equality.
	 * Field names are ignored in this comparison.
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Schema))
			return false;
		Schema otherSchema = (Schema) obj;
		if (version != otherSchema.version ||
			!keyType.getClass().equals(otherSchema.keyType.getClass()) ||
			fieldClasses.length != otherSchema.fieldClasses.length)
			return false;
		for (int i = 0; i < fieldClasses.length; i++) {
			if (!fieldClasses[i].getClass().equals(otherSchema.fieldClasses[i].getClass()))
				return false;
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder buf = new StringBuilder();
		buf.append(keyName);
		buf.append("(key,");
		buf.append(keyType.getClass().getSimpleName());
		buf.append(")");
		for (int i = 0; i < fieldNames.length; i++) {
			buf.append("\n");
			buf.append(fieldNames[i]);
			buf.append("(");
			buf.append(fieldClasses[i].getSimpleName());
			buf.append(")");
		}
		return buf.toString();
	}

}
