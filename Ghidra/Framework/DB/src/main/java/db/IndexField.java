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

import db.buffers.DataBuffer;
import ghidra.util.exception.AssertException;

/**
 * <code>IndexField</code> provides a index table primary key {@link Field} 
 * implementation which wraps both the index field value (fixed or varaible length) 
 * and its' corresponding primary key (fixed or variable length). 
 */
class IndexField extends Field {

	static final int MAX_INDEX_FIELD_LENGTH = 64;

	private Field primaryKey;
	private Field nonTruncatedIndexedField;
	private Field indexedField;
	private boolean isTruncated = false;

	/**
	 * Construct an index field with an initial value.
	 * @param indexedField indexed field value
	 * @param primaryKey primary key value
	 */
	IndexField(Field indexedField, Field primaryKey) {
		if (primaryKey.isVariableLength()) {
			throw new IllegalArgumentException("variable length primaryKey not supported");
		}
		this.primaryKey = primaryKey.copyField();
		this.nonTruncatedIndexedField = indexedField;
		this.indexedField = indexedField;
		if (indexedField.isVariableLength() && indexedField.length() >= MAX_INDEX_FIELD_LENGTH) {
			// Ensure that we do not exceed the maximum allowed index key length
			// and conserves space when indexing very long values
			this.indexedField = indexedField.copyField();
			this.indexedField.truncate(MAX_INDEX_FIELD_LENGTH);
			isTruncated = true;
		}
	}

	@Override
	boolean isNull() {
		return false; // not-applicable
	}

	@Override
	void setNull() {
		throw new IllegalFieldAccessException("Index field may not be set null");
	}

	/**
	 * Get the indexed field value.  If the original value exceeded 
	 * {@link #MAX_INDEX_FIELD_LENGTH} in length the returned value will
	 * be truncated.
	 * @return indexed field value
	 */
	Field getIndexedField() {
		return indexedField;
	}

	/**
	 * Get the non-truncated index field value.
	 * @return non-truncated index field value.
	 * @deprecated this method serves no real purpose since the non-truncated
	 * indexed field value is not retained within the index table.
	 */
	@Deprecated
	Field getNonTruncatedIndexField() {
		return nonTruncatedIndexedField;
	}

	/**
	 * Determine if the index field value has been truncated from its' original
	 * value.
	 * @return true if truncated else false
	 * @deprecated this method serves no real purpose since the truncation 
	 * status is not retained within the index table.
	 */
	@Deprecated
	boolean usesTruncatedFieldValue() {
		return isTruncated;
	}

	Field getPrimaryKey() {
		return primaryKey;
	}

	@Override
	int length() {
		return indexedField.length() + primaryKey.length();
	}

	@Override
	int write(Buffer buf, int offset) throws IOException {
		offset = indexedField.write(buf, offset);
		return primaryKey.write(buf, offset);
	}

	@Override
	int read(Buffer buf, int offset) throws IOException {
		offset = indexedField.read(buf, offset);
		return primaryKey.read(buf, offset);
	}

	@Override
	int readLength(Buffer buf, int offset) throws IOException {
		return indexedField.readLength(buf, offset) + primaryKey.length();
	}

	@Override
	public boolean isVariableLength() {
		return indexedField.isVariableLength();
	}

	@Override
	public IndexField copyField() {
		return new IndexField(indexedField.copyField(), primaryKey.copyField());
	}

	@Override
	public IndexField newField() {
		return new IndexField(indexedField.newField(), primaryKey.newField());
	}

	/**
	 * Construct a new {@link IndexField} instance for the given indexValue and 
	 * associated primary key.  These fields are verified against this instance to 
	 * ensure that they are of the correct type.
	 * @param indexValue column field value to be indexed
	 * @param key primary key associated with indexValue
	 * @return new IndexField instance
	 */
	IndexField newIndexField(Field indexValue, Field key) {
		if (!indexValue.isSameType(indexedField) || !primaryKey.isSameType(getPrimaryKey())) {
			throw new IllegalArgumentException("incorrect index value or key type");

		}
		return new IndexField(indexValue, key);
	}

	@Override
	final IndexField getMinValue() {
		throw new UnsupportedOperationException();
	}

	@Override
	final IndexField getMaxValue() {
		throw new UnsupportedOperationException();
	}

	@Override
	byte getFieldType() {
		return getIndexFieldType(indexedField, primaryKey);
	}

	@Override
	public String toString() {
		return indexedField + "/" + primaryKey;
	}

	@Override
	public String getValueAsString() {
		return indexedField.getValueAsString() + " / " + primaryKey.getValueAsString();
	}

	boolean hasSameIndexValue(IndexField field) {
		if (field == null) {
			return false;
		}
		if (indexedField == null) {
			return field.indexedField == null;
		}
		return indexedField.equals(field.indexedField);
	}

	@Override
	public byte[] getBinaryData() {
		byte[] indexBytes = indexedField.getBinaryData();
		byte[] primaryKeyBytes = primaryKey.getBinaryData();
		int len = indexBytes.length + primaryKeyBytes.length;
		byte[] bytes = new byte[len];
		System.arraycopy(indexBytes, 0, bytes, 0, indexBytes.length);
		System.arraycopy(primaryKeyBytes, 0, bytes, indexBytes.length, primaryKeyBytes.length);
		return bytes;
	}

	@Override
	public void setBinaryData(byte[] bytes) {
		if (isVariableLength()) {
			throw new IllegalFieldAccessException("Unsupported for variable length IndexField");
		}
		if (bytes.length != length()) {
			throw new IllegalFieldAccessException();
		}
		BinaryDataBuffer buffer = new BinaryDataBuffer(bytes);
		try {
			read(buffer, 0);
		}
		catch (IOException e) {
			throw new IllegalFieldAccessException();
		}
	}

	@Override
	public int compareTo(Field o) {
		IndexField f = (IndexField) o;
		int result = indexedField.compareTo(f.indexedField);
		if (result != 0) {
			return result;
		}
		return primaryKey.compareTo(f.primaryKey);
	}

	@Override
	int compareTo(DataBuffer buffer, int offset) {
		int result = indexedField.compareTo(buffer, offset);
		if (result != 0) {
			return result;
		}
		try {
			int indexedFieldLen = indexedField.readLength(buffer, offset);
			return primaryKey.compareTo(buffer, offset + indexedFieldLen);
		}
		catch (IOException e) {
			throw new AssertException(e); // DataBuffer does not throw IOException
		}
	}

	@Override
	public boolean isSameType(Field field) {
		if (!(field instanceof IndexField)) {
			return false;
		}
		IndexField otherField = (IndexField) field;
		return indexedField.isSameType(otherField.indexedField) &&
			primaryKey.isSameType(otherField.primaryKey);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null || obj.getClass() != getClass()) {
			return false;
		}
		IndexField f = (IndexField) obj;
		return primaryKey.equals(f.primaryKey) && indexedField.equals(f.indexedField);
	}

	@Override
	public int hashCode() {
		return (indexedField.hashCode() * 31) + primaryKey.hashCode();
	}

	static byte getIndexFieldType(Field indexedFieldType, Field primaryKeyFieldType) {
		if (primaryKeyFieldType instanceof IndexField) {
			throw new IllegalArgumentException();
		}
		if (indexedFieldType instanceof IndexField) {
			throw new IllegalArgumentException();
		}
		return (byte) ((primaryKeyFieldType.getFieldType() << INDEX_FIELD_TYPE_SHIFT) |
			indexedFieldType.getFieldType());

	}

	/**
	 * Get the index field associated with the specified encoded field type.
	 * @param fieldType field type
	 * @return IndexField
	 * @throws UnsupportedFieldException if unsupported fieldType specified
	 */
	static IndexField getIndexField(byte fieldType) throws UnsupportedFieldException {
		Field indexedField = Field.getField((byte) (fieldType & FIELD_TYPE_MASK));

		byte primaryKeyFeldType = (byte) (fieldType >> INDEX_FIELD_TYPE_SHIFT & FIELD_TYPE_MASK);
		if (primaryKeyFeldType == FIELD_RESERVED_15_TYPE) {
			// 0xf0..0xff - Reserved for Schema use
			throw new UnsupportedFieldException(fieldType);
		}
		if (primaryKeyFeldType == LEGACY_INDEX_LONG_TYPE) {
			return new LegacyIndexField(indexedField);
		}

		Field primaryKeyType = Field.getField(primaryKeyFeldType);
		return new IndexField(indexedField, primaryKeyType);
	}

}
