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

/**
 * <code>LegacyIndexField</code> supports legacy index tables where the indexed
 * field was a {@link LongField} and improperly employed a variable-length
 * index storage scheme when the primary key was a LongField.
 */
class LegacyIndexField extends IndexField {

	/**
	 * Constructor
	 * @param indexField primary table field type being indexed
	 */
	LegacyIndexField(Field indexField) {
		super(indexField, new LongField());
	}

	private LegacyIndexField(Field indexField, LongField primaryKey) {
		super(indexField, primaryKey);
	}

	@Override
	public boolean isVariableLength() {
		// NOTE: while fixed-length IndexFields are possible this past
		// oversight failed to override this method for fixed-length cases
		// (e.g., indexing fixed-length field with long primary key).
		// To preserve backward compatibility this can not be changed for 
		// long primary keys.
		return true;
	}

	@Override
	public boolean equals(Object obj) {
		return (obj instanceof LegacyIndexField) && super.equals(obj);
	}

	@Override
	LegacyIndexField newIndexField(Field indexValue, Field primaryKey) {
		if (!indexValue.isSameType(getIndexedField()) || !(primaryKey instanceof LongField)) {
			throw new IllegalArgumentException("incorrect index value or key type");

		}
		return new LegacyIndexField(indexValue, (LongField) primaryKey);
	}

}
