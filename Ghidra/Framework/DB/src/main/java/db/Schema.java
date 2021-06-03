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

import java.util.*;

import org.apache.commons.lang3.ArrayUtils;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableSet.Builder;
import com.google.common.primitives.Bytes;

import db.Field.UnsupportedFieldException;
import ghidra.util.exception.AssertException;

/**
 * Class for definining the columns in a Ghidra Database table.
 */
public class Schema {

	private static final String NAME_SEPARATOR = ";";

	static final byte FIELD_EXTENSION_INDICATOR = -1;

	private static final byte SPARSE_FIELD_LIST_EXTENSION = 1;

	private int version;

	private Field keyType;
	private String keyName;

	private Field[] fields;
	private String[] fieldNames;
	private Set<Integer> sparseColumnSet;

	private boolean isVariableLength;
	private int fixedLength;

	private boolean forceUseVariableLengthKeyNodes;

	/**
	 * Construct a new Schema.
	 * @param version schema version
	 * @param keyField field associated with primary key (representative instance)
	 * @param keyName primary key name
	 * @param fields array of column fields (representative instances)
	 * @param fieldNames array of column field names
	 * @param sparseColumns column indexes corresponding to those
	 * columns which utilize sparse storage (null if no sparse columns).  
	 * Valid sparse column indexes are in the range 0..127.
	 * @throws IllegalArgumentException invalid parameters
	 */
	public Schema(int version, Field keyField, String keyName, Field[] fields,
			String[] fieldNames, int[] sparseColumns) {
		this.version = version;
		this.keyType = keyField;
		this.keyName = keyName;
		this.fields = fields;
		this.fieldNames = fieldNames;
		if (fields.length != fieldNames.length) {
			throw new IllegalArgumentException("fieldNames and fields lengths differ");
		}
		isVariableLength = false;
		fixedLength = 0;
		for (int colIndex = 0; colIndex < fields.length; colIndex++) {
			Field field = fields[colIndex];
			if (field.isVariableLength()) {
				isVariableLength = true;
			}
			fixedLength += field.length();
			if (fieldNames[colIndex].indexOf(NAME_SEPARATOR) >= 0) {
				throw new IllegalArgumentException("field names may not contain ';'");
			}
		}
		try {
			initializeSparseColumnSet(ArrayUtils.toObject(sparseColumns));
		}
		catch (UnsupportedFieldException e) {
			throw new IllegalArgumentException(e);
		}
		if (isVariableLength) {
			fixedLength = 0;
		}
	}

	/**
	 * Construct a new Schema.
	 * @param version schema version
	 * @param keyField field associated with primary key (representative instance)
	 * @param keyName primary key name
	 * @param fields array of column fields (representative instances)
	 * @param fieldNames array of column field names
	 * @throws IllegalArgumentException invalid parameters
	 */
	public Schema(int version, Field keyField, String keyName, Field[] fields,
			String[] fieldNames) {
		this(version, keyField, keyName, fields, fieldNames, null);
	}

	/**
	 * Construct a new Schema which uses a long key.
	 * @param version schema version
	 * @param keyName primary key name
	 * @param fields array of column fields (representative instances)
	 * @param fieldNames array of column field names
	 * @throws IllegalArgumentException invalid parameters
	 */
	public Schema(int version, String keyName, Field[] fields, String[] fieldNames) {
		this(version, LongField.INSTANCE, keyName, fields, fieldNames, null);
	}

	/**
	 * Construct a new Schema which uses a long key.
	 * @param version schema version
	 * @param keyName primary key name
	 * @param fields array of column fields (representative instances)
	 * @param fieldNames array of column field names
	 * @param sparseColumns column indexes corresponding to those
	 * columns which utilize sparse storage (null if no sparse columns).
	 * Valid sparse column indexes are in the range 0..127.
	 * @throws IllegalArgumentException invalid parameters
	 */
	public Schema(int version, String keyName, Field[] fields, String[] fieldNames,
			int[] sparseColumns) {
		this(version, LongField.INSTANCE, keyName, fields, fieldNames, sparseColumns);
	}

	/**
	 * Construct a new Schema.
	 * @param version schema version
	 * @param keyClass field class associated with primary key
	 * @param keyName primary key name
	 * @param fieldClasses array of column field classes
	 * @param fieldNames array of column field names
	 * @throws IllegalArgumentException invalid parameters
	 */
	public Schema(int version, Class<?> keyClass, String keyName, Class<?>[] fieldClasses,
			String[] fieldNames) {
		this(version, getField(keyClass), keyName, getFields(fieldClasses), fieldNames, null);
	}

	/**
	 * Construct a new Schema.
	 * @param version schema version
	 * @param keyClass field class associated with primary key
	 * @param keyName primary key name
	 * @param fieldClasses array of column field classes
	 * @param fieldNames array of column field names
	 * @param sparseColumns column indexes corresponding to those
	 * columns which utilize sparse storage (null if no sparse columns).
	 * Valid sparse column indexes are in the range 0..127.
	 * @throws IllegalArgumentException invalid parameters
	 */
	public Schema(int version, Class<?> keyClass, String keyName, Class<?>[] fieldClasses,
			String[] fieldNames, int[] sparseColumns) {
		this(version, getField(keyClass), keyName, getFields(fieldClasses), fieldNames,
			sparseColumns);
	}

	/**
	 * Construct a new Schema which uses a long key.
	 * @param version schema version
	 * @param keyName primary key name
	 * @param fieldClasses array of column field classes
	 * @param fieldNames array of column field names
	 * @throws IllegalArgumentException invalid parameters
	 */
	public Schema(int version, String keyName, Class<?>[] fieldClasses, String[] fieldNames) {
		this(version, LongField.INSTANCE, keyName, getFields(fieldClasses), fieldNames, null);
	}

	/**
	 * Construct a new Schema which uses a long key.
	 * @param version schema version
	 * @param keyName primary key name
	 * @param fieldClasses array of column field classes
	 * @param fieldNames array of column field names
	 * @param sparseColumns column indexes corresponding to those
	 * columns which utilize sparse storage (null if no sparse columns).
	 * Valid sparse column indexes are in the range 0..127.
	 * @throws IllegalArgumentException invalid parameters
	 */
	public Schema(int version, String keyName, Class<?>[] fieldClasses, String[] fieldNames,
			int[] sparseColumns) {
		this(version, LongField.INSTANCE, keyName, getFields(fieldClasses), fieldNames,
			sparseColumns);
	}

	/**
	 * Construct a Schema based upon encoded
	 * @param version schema version
	 * @param encodedKeyFieldType key field type
	 * @param encodedFieldTypes encoded field types array.
	 * @param packedFieldNames packed list of field names separated by ';'.
	 * The first field name corresponds to the key name.
	 * @throws UnsupportedFieldException if unsupported fieldType specified
	 */
	Schema(int version, byte encodedKeyFieldType, byte[] encodedFieldTypes, String packedFieldNames)
			throws UnsupportedFieldException {
		this.version = version;
		this.keyType = Field.getField(encodedKeyFieldType);
		parseNames(packedFieldNames);
		isVariableLength = false;
		fixedLength = 0;

		initializeFields(encodedFieldTypes); // initializes fields and sparseColumns

		if (fieldNames.length != fields.length) {
			throw new IllegalArgumentException("fieldNames and column types differ in length");
		}
	}

	/**
	 * Determine if schema employs sparse column storage
	 * @return true if schema employs sparse column storage
	 */
	public boolean hasSparseColumns() {
		return sparseColumnSet != null;
	}

	/**
	 * Determine if the specified column index has been designated as a sparse
	 * column within the associated record storage
	 * @param columnIndex column index
	 * @return true if designated column uses sparse storage
	 */
	public boolean isSparseColumn(int columnIndex) {
		return sparseColumnSet != null && sparseColumnSet.contains(columnIndex);
	}

	/**
	 * Initialize field types and related field extensions (e.g., sparse field list).
	 * The presence of field extensions within the encodedFieldTypes is indicated by a
	 * -1 (field extension indicator) following the encoded field types.  
	 * The byte value following the field extension indicator
	 * is the extension type which is followed by the extension data if applicable.
	 * A -1 byte is used to separate each extension byte sequence.
	 * @param encodedFieldTypes encoded field type data
	 * @throws UnsupportedFieldException if decoding of the encodedFieldTypes fails
	 */
	private void initializeFields(byte[] encodedFieldTypes) throws UnsupportedFieldException {

		if (encodedFieldTypes.length == 0) {
			fields = new Field[0];
			return;
		}

		int index = 0;

		ArrayList<Field> fieldList = new ArrayList<>();
		while (index < encodedFieldTypes.length) {
			byte b = encodedFieldTypes[index++];
			if (b == FIELD_EXTENSION_INDICATOR) {
				break;
			}
			Field f = Field.getField(b);
			fieldList.add(f);
			if (f.isVariableLength()) {
				isVariableLength = true;
			}
			fixedLength += f.length();
		}
		fields = fieldList.toArray(new Field[fieldList.size()]);

		while (index < encodedFieldTypes.length) {
			int extensionType = encodedFieldTypes[index++];
			if (extensionType == SPARSE_FIELD_LIST_EXTENSION) {
				index += parseSparseColumnIndexes(encodedFieldTypes, index);
			}
			else {
				throw new UnsupportedFieldException(
					"Unsupported field extension type: " + extensionType);
			}
		}

		if (isVariableLength) {
			fixedLength = 0;
		}
	}

	private void initializeSparseColumnSet(Integer[] sparseColumns) throws UnsupportedFieldException {
		if (sparseColumns == null || sparseColumns.length == 0) {
			return;
		}
		Builder<Integer> builder = ImmutableSet.builder();
		for (int i : sparseColumns) {
			if (i < 0 || i > Byte.MAX_VALUE || i >= fields.length) {
				throw new UnsupportedFieldException("Sparse column entry out of range: " + i);
			}
			builder.add(i);
		}
		sparseColumnSet = builder.build();
		if (sparseColumnSet.size() != sparseColumns.length) {
			throw new UnsupportedFieldException("Sparse column set contains duplicate entry");
		}
		isVariableLength = true; // sparse records are variable length
	}

	/**
	 * Parse the sparse column indexes contained within the encodedFieldTypes data
	 * @param encodedFieldTypes encoded data bytes
	 * @param index of first extension data byte within encodedFieldTypes array
	 * @return number of encoded data bytes consumed
	 */
	private int parseSparseColumnIndexes(byte[] encodedFieldTypes, int index)
			throws UnsupportedFieldException {
		try {
			int consumed = 0;
			ArrayList<Integer> columnIndexes = new ArrayList<>();
			while (index < encodedFieldTypes.length &&
				encodedFieldTypes[index] != FIELD_EXTENSION_INDICATOR) {
				columnIndexes.add((int) encodedFieldTypes[index++]);
				++consumed;
			}
			Integer[] sparseColumns = columnIndexes.toArray(new Integer[columnIndexes.size()]);
			initializeSparseColumnSet(sparseColumns);
			return consumed;
		}
		catch (ArrayIndexOutOfBoundsException e) {
			throw new UnsupportedFieldException("Incomplete sparse column data");
		}
	}

	private static Field getField(Class<?> fieldClass) {
		if (!Field.class.isAssignableFrom(fieldClass) || fieldClass == Field.class ||
			IndexField.class.isAssignableFrom(fieldClass)) {
			throw new IllegalArgumentException("Invalid Field class: " + fieldClass.getName());
		}
		try {
			return (Field) fieldClass.getConstructor().newInstance();
		}
		catch (Exception e) {
			throw new RuntimeException("Failed to construct: " + fieldClass.getName(), e);
		}
	}

	private static Field[] getFields(Class<?>[] fieldClasses) {
		Field[] fields = new Field[fieldClasses.length];
		for (int i = 0; i < fieldClasses.length; i++) {
			fields[i] = getField(fieldClasses[i]);
		}
		return fields;
	}

	/**
	 * Determine if this schema can use LongKeyNode's within a table.
	 * @return true if LongKeyNode's can be used to store records produced with this schema.
	 */
	boolean useLongKeyNodes() {
		return !forceUseVariableLengthKeyNodes && keyType instanceof LongField;
	}

	/**
	 * Determine if this schema uses VarKeyNode's within a table.
	 * @return true if VarKeyNode's are be used to store records produced with this schema.
	 */
	boolean useVariableKeyNodes() {
		return forceUseVariableLengthKeyNodes || keyType.isVariableLength();
	}

	/**
	 * Determine if this schema can use FixedKeyNode's within a table.
	 * @return true if FixedKeyNode's can be used to store records produced with this schema.
	 */
	boolean useFixedKeyNodes() {
		return !useVariableKeyNodes() && !useLongKeyNodes();
	}

	/**
	 * Force use of variable-length key nodes.
	 * <br>
	 * This method provides a work-around for legacy schemas which
	 * employ primitive fixed-length keys other than LongField
	 * and improperly employ a variable-length-key storage schema.
	 * Although rare, this may be neccessary to ensure backward compatibility 
	 * with legacy DB storage (example ByteField key employed by old table).
	 */
	void forceUseOfVariableLengthKeyNodes() {
		forceUseVariableLengthKeyNodes = true;
	}

	/**
	 * Get the Field type for the key.
	 * @return key Field type
	 */
	public Field getKeyFieldType() {
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
	public Field[] getFields() {
		return fields;
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
		return fields.length;
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
		for (String fieldName : fieldNames) {
			buf.append(fieldName);
			buf.append(NAME_SEPARATOR);
		}
		return buf.toString();
	}

	byte getEncodedKeyFieldType() {
		return keyType.getFieldType();
	}

	/**
	 * Get the schema field types as an encoded byte array.
	 * @return byte[] field type list as an encoded byte array.
	 */
	byte[] getEncodedFieldTypes() {
		ArrayList<Byte> encodedDataList = new ArrayList<>();

		// add field type encodings
		for (Field field : fields) {
			encodedDataList.add(field.getFieldType());
		}

		// add sparse field extension data
		if (sparseColumnSet != null) {
			encodedDataList.add(FIELD_EXTENSION_INDICATOR);
			encodedDataList.add(SPARSE_FIELD_LIST_EXTENSION);
			for (int col : sparseColumnSet) {
				encodedDataList.add((byte) col);
			}
		}
		return Bytes.toArray(encodedDataList);
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
	 * @param key long key
	 * @return new record
	 */
	public DBRecord createRecord(long key) {
		return createRecord(new LongField(key));
	}

	/**
	 * Create an empty record for the specified key.
	 * @param key record key field
	 * @return new record
	 */
	public DBRecord createRecord(Field key) {
		return hasSparseColumns() ? new SparseRecord(this, key) : new DBRecord(this, key);
	}

	/**
	 * Get a new instance of a data Field object for the specified column.
	 * @param colIndex field index
	 * @return new Field object suitable for data reading/writing.
	 */
	Field getField(int colIndex) {
		try {
			return fields[colIndex].newField();
		}
		catch (Exception e) {
			throw new AssertException(e.getMessage());
		}
	}

	/**
	 * Compare two schemas for equality.
	 * Field names are ignored in this comparison.  Instance variables such as {@link #fixedLength},
	 * {@link Schema#isVariableLength} and {@link #forceUseVariableLengthKeyNodes} are also ignored.
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Schema)) {
			return false;
		}
		Schema otherSchema = (Schema) obj;
		if (version != otherSchema.version ||
			!keyType.getClass().equals(otherSchema.keyType.getClass()) ||
			fields.length != otherSchema.fields.length) {
			return false;
		}
		for (int i = 0; i < fields.length; i++) {
			if (!fields[i].getClass().equals(otherSchema.fields[i].getClass())) {
				return false;
			}
		}
		if (!Objects.equals(sparseColumnSet, otherSchema.sparseColumnSet)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		// Schemas are not intended to be hashed
		return super.hashCode();
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
			buf.append(fields[i].getClass().getSimpleName());
			buf.append(")");
		}
		return buf.toString();
	}

}
