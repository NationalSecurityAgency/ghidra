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

abstract class IndexField extends Field {

	private static final int MAX_INDEX_FIELD_LENGTH = 64;

	private long primaryKey;
	private Field nonTruncatedIndexField;
	private Field indexField;
	private boolean isTruncated = false;

	/**
	 * Construct a new index field with an initial value of null.
	 */
	IndexField(Field newIndexField) {
		indexField = newIndexField;
		nonTruncatedIndexField = newIndexField;
	}

	/**
	 * Construct an index field with an initial value.
	 */
	IndexField(Field value, long primaryKey) {
		this.nonTruncatedIndexField = value;
		indexField = value.newField(value);
		if (indexField.isVariableLength() && indexField.length() >= MAX_INDEX_FIELD_LENGTH) {
			// Ensure that we do not exceed the maximum allowed index key length
			// and conserves space when indexing very long values
			indexField.truncate(MAX_INDEX_FIELD_LENGTH);
			isTruncated = true;
		}
		this.primaryKey = primaryKey;
	}

	Field getIndexField() {
		return indexField;
	}

	Field getNonTruncatedIndexField() {
		return nonTruncatedIndexField;
	}

	boolean usesTruncatedFieldValue() {
		return isTruncated;
	}

	long getPrimaryKey() {
		return primaryKey;
	}

	/*
	 * @see ghidra.framework.store.db.Field#length()
	 */
	@Override
	int length() {
		return indexField.length() + 8;
	}

	/*
	 * @see ghidra.framework.store.db.Field#write(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int write(Buffer buf, int offset) throws IOException {
		offset = indexField.write(buf, offset);
		return buf.putLong(offset, primaryKey);
	}

	/*
	 * @see ghidra.framework.store.db.Field#read(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int read(Buffer buf, int offset) throws IOException {
		offset = indexField.read(buf, offset);
		primaryKey = buf.getLong(offset);
		return offset + 8;
	}

	/*
	 * @see ghidra.framework.store.db.Field#readLength(ghidra.framework.store.Buffer, int)
	 */
	@Override
	int readLength(Buffer buf, int offset) throws IOException {
		return indexField.readLength(buf, offset) + 8;
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
	protected abstract byte getFieldType();

	abstract String getFieldTypeString();

	/*
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return getFieldTypeString() + ": " + indexField;
	}

	@Override
	public String getValueAsString() {
		return indexField.getValueAsString() + " + " + Long.toHexString(primaryKey);
	}

	boolean hasSameIndex(IndexField field) {
		if (field == null) {
			return false;
		}
		if (indexField == null) {
			return field.indexField == null;
		}
		return indexField.equals(field.indexField);
	}

	/*
	 * @see ghidra.framework.store.db.Field#getBinaryData()
	 */
	@Override
	public byte[] getBinaryData() {
		byte[] indexBytes = indexField.getBinaryData();
		int len = indexBytes.length;
		byte[] bytes = new byte[len + 8];
		System.arraycopy(indexBytes, 0, bytes, 0, len);

		bytes[len] = (byte) (primaryKey >> 56);
		bytes[++len] = (byte) (primaryKey >> 48);
		bytes[++len] = (byte) (primaryKey >> 40);
		bytes[++len] = (byte) (primaryKey >> 32);
		bytes[++len] = (byte) (primaryKey >> 24);
		bytes[++len] = (byte) (primaryKey >> 16);
		bytes[++len] = (byte) (primaryKey >> 8);
		bytes[++len] = (byte) primaryKey;

		return bytes;
	}

	/*
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(Field o) {
		IndexField f = (IndexField) o;
		int result = indexField.compareTo(f.indexField);
		if (result != 0) {
			return result;
		}
		if (primaryKey == f.primaryKey) {
			return 0;
		}
		else if (primaryKey < f.primaryKey) {
			return -1;
		}
		return 1;
	}

	/*
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (!getClass().isInstance(obj))
			return false;
		IndexField f = (IndexField) obj;
		return primaryKey == f.primaryKey && indexField.equals(f.indexField);
	}

	/*
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return (int) primaryKey;
	}

	/**
	 * Get the field associated with the specified type value.
	 * @param fieldType
	 * @return Field
	 */
	static IndexField getIndexField(byte fieldType) {
		switch (fieldType & BASE_TYPE_MASK) {
			case LONG_TYPE:
				return new LongIndexField();
			case INT_TYPE:
				return new IntIndexField();
			case STRING_TYPE:
				return new StringIndexField();
			case SHORT_TYPE:
				return new ShortIndexField();
			case BYTE_TYPE:
				return new ByteIndexField();
			case BOOLEAN_TYPE:
				return new BooleanIndexField();
			case BINARY_OBJ_TYPE:
				return new BinaryIndexField();
		}
		throw new AssertException();
	}

	static IndexField getIndexField(Field indexedField, long primaryKey) {
		switch (indexedField.getFieldType()) {
			case LONG_TYPE:
				return new LongIndexField((LongField) indexedField, primaryKey);
			case INT_TYPE:
				return new IntIndexField((IntField) indexedField, primaryKey);
			case STRING_TYPE:
				return new StringIndexField((StringField) indexedField, primaryKey);
			case SHORT_TYPE:
				return new ShortIndexField((ShortField) indexedField, primaryKey);
			case BYTE_TYPE:
				return new ByteIndexField((ByteField) indexedField, primaryKey);
			case BOOLEAN_TYPE:
				return new BooleanIndexField((BooleanField) indexedField, primaryKey);
			case BINARY_OBJ_TYPE:
				return new BinaryIndexField((BinaryField) indexedField, primaryKey);
		}
		throw new AssertException();
	}

	private static class LongIndexField extends IndexField {

		LongIndexField() {
			super(new LongField());
		}

		LongIndexField(LongField indexedField, long primaryKey) {
			super(indexedField, primaryKey);
		}

		@Override
		protected byte getFieldType() {
			return INDEX_TYPE_FLAG | LONG_TYPE;
		}

		@Override
		String getFieldTypeString() {
			return "LongIndexField";
		}

		@Override
		public Field newField(Field fieldValue) {
			if (!(fieldValue instanceof LongIndexField)) {
				throw new AssertException();
			}
			LongIndexField f = (LongIndexField) fieldValue;
			return new LongIndexField((LongField) f.getIndexField(), f.getPrimaryKey());
		}

		@Override
		public Field newField() {
			return new LongIndexField();
		}

	}

	private static class IntIndexField extends IndexField {

		IntIndexField() {
			super(new IntField());
		}

		IntIndexField(IntField indexedField, long primaryKey) {
			super(indexedField, primaryKey);
		}

		@Override
		protected byte getFieldType() {
			return INDEX_TYPE_FLAG | INT_TYPE;
		}

		@Override
		String getFieldTypeString() {
			return "IntIndexField";
		}

		@Override
		public Field newField(Field fieldValue) {
			if (!(fieldValue instanceof IntIndexField)) {
				throw new AssertException();
			}
			IntIndexField f = (IntIndexField) fieldValue;
			return new IntIndexField((IntField) f.getIndexField(), f.getPrimaryKey());
		}

		@Override
		public Field newField() {
			return new IntIndexField();
		}

	}

	private static class StringIndexField extends IndexField {

		StringIndexField() {
			super(new StringField());
		}

		StringIndexField(StringField indexedField, long primaryKey) {
			super(indexedField, primaryKey);
		}

		@Override
		protected byte getFieldType() {
			return INDEX_TYPE_FLAG | STRING_TYPE;
		}

		@Override
		String getFieldTypeString() {
			return "StringIndexField";
		}

		@Override
		public Field newField(Field fieldValue) {
			if (!(fieldValue instanceof StringIndexField)) {
				throw new AssertException();
			}
			StringIndexField f = (StringIndexField) fieldValue;
			return new StringIndexField((StringField) f.getIndexField(), f.getPrimaryKey());
		}

		@Override
		public Field newField() {
			return new StringIndexField();
		}

	}

	private static class ShortIndexField extends IndexField {

		ShortIndexField() {
			super(new ShortField());
		}

		ShortIndexField(ShortField indexedField, long primaryKey) {
			super(indexedField, primaryKey);
		}

		@Override
		protected byte getFieldType() {
			return INDEX_TYPE_FLAG | SHORT_TYPE;
		}

		@Override
		String getFieldTypeString() {
			return "ShortIndexField";
		}

		@Override
		public Field newField(Field fieldValue) {
			if (!(fieldValue instanceof ShortIndexField)) {
				throw new AssertException();
			}
			ShortIndexField f = (ShortIndexField) fieldValue;
			return new ShortIndexField((ShortField) f.getIndexField(), f.getPrimaryKey());
		}

		@Override
		public Field newField() {
			return new ShortIndexField();
		}

	}

	private static class ByteIndexField extends IndexField {

		ByteIndexField() {
			super(new ByteField());
		}

		ByteIndexField(ByteField indexedField, long primaryKey) {
			super(indexedField, primaryKey);
		}

		@Override
		protected byte getFieldType() {
			return INDEX_TYPE_FLAG | BYTE_TYPE;
		}

		@Override
		String getFieldTypeString() {
			return "ByteIndexField";
		}

		@Override
		public Field newField(Field fieldValue) {
			if (!(fieldValue instanceof ByteIndexField)) {
				throw new AssertException();
			}
			ByteIndexField f = (ByteIndexField) fieldValue;
			return new ByteIndexField((ByteField) f.getIndexField(), f.getPrimaryKey());
		}

		@Override
		public Field newField() {
			return new ByteIndexField();
		}

	}

	private static class BooleanIndexField extends IndexField {

		BooleanIndexField() {
			super(new BooleanField());
		}

		BooleanIndexField(BooleanField indexedField, long primaryKey) {
			super(indexedField, primaryKey);
		}

		@Override
		protected byte getFieldType() {
			return INDEX_TYPE_FLAG | BOOLEAN_TYPE;
		}

		@Override
		String getFieldTypeString() {
			return "BooleanIndexField";
		}

		@Override
		public Field newField(Field fieldValue) {
			if (!(fieldValue instanceof BooleanIndexField)) {
				throw new AssertException();
			}
			BooleanIndexField f = (BooleanIndexField) fieldValue;
			return new BooleanIndexField((BooleanField) f.getIndexField(), f.getPrimaryKey());
		}

		@Override
		public Field newField() {
			return new BooleanIndexField();
		}

	}

	private static class BinaryIndexField extends IndexField {

		BinaryIndexField() {
			super(new BinaryField());
		}

		BinaryIndexField(BinaryField indexedField, long primaryKey) {
			super(indexedField, primaryKey);
		}

		@Override
		protected byte getFieldType() {
			return INDEX_TYPE_FLAG | BINARY_OBJ_TYPE;
		}

		@Override
		String getFieldTypeString() {
			return "BinaryIndexField";
		}

		@Override
		public Field newField(Field fieldValue) {
			if (!(fieldValue instanceof BinaryIndexField)) {
				throw new AssertException();
			}
			BinaryIndexField f = (BinaryIndexField) fieldValue;
			return new BinaryIndexField((BinaryField) f.getIndexField(), f.getPrimaryKey());
		}

		@Override
		public Field newField() {
			return new BinaryIndexField();
		}

	}
}
