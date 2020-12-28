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
package ghidra.program.database.properties;

import db.*;
import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;

/**
 * <code>GenericSaveable</code> is used by the <code>DBPropertyMapManager</code>
 * when the class can not be found and loaded for the class path name of a 
 * property in the database. This allows the properties for that class to be 
 * accessed in a generic way so that the manager can copy or remove the property 
 * at a particular address. This allows the Diff and MultiUser Merge to compare 
 * and manipulate the property as needed.
 */
public class GenericSaveable implements Saveable {

	final DBRecord record;
	final Schema schema;
	final Class<?>[] fieldClasses = new Class<?>[0];

	/**
	 * Creates a generic saveable that can be used by the property map manager
	 * via the saveable's record and associated database schema
	 * @param record the saveable's record.
	 * @param schema the saveable's database table's schema.
	 */
	GenericSaveable(DBRecord record, Schema schema) {
		this.record = record;
		this.schema = schema;
	}

	@Override
	public Class<?>[] getObjectStorageFields() {
		return fieldClasses;
	}

	/* (non-Javadoc)
	 * @see ghidra.util.Saveable#save(ghidra.util.ObjectStorage)
	 */
	@Override
	public void save(ObjectStorage objStorage) {
	}

	/* (non-Javadoc)
	 * @see ghidra.util.Saveable#restore(ghidra.util.ObjectStorage)
	 */
	@Override
	public void restore(ObjectStorage objStorage) {
	}

	/* (non-Javadoc)
	 * @see ghidra.util.Saveable#getSchemaVersion()
	 */
	@Override
	public int getSchemaVersion() {
		return 0;
	}

	/* (non-Javadoc)
	 * @see ghidra.util.Saveable#isUpgradeable(int)
	 */
	@Override
	public boolean isUpgradeable(int oldSchemaVersion) {
		return false;
	}

	/* (non-Javadoc)
	 * @see ghidra.util.Saveable#upgrade(ghidra.util.ObjectStorage, int, ghidra.util.ObjectStorage)
	 */
	@Override
	public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion,
			ObjectStorage currentObjStorage) {
		return false;
	}

	@Override
	public boolean isPrivate() {
		return false;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((record == null) ? 0 : record.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		GenericSaveable other = (GenericSaveable) obj;
		if (record == null) {
			if (other.record != null) {
				return false;
			}
		}
		else if (!record.equals(other.record)) {
			return false;
		}
		return true;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		if (record == null || schema == null) {
			return super.toString();
		}
		StringBuffer buf = new StringBuffer();
		String[] fieldNames = schema.getFieldNames();
		int numFields = fieldNames.length;
		for (int i = 0; i < numFields; i++) {
			Field field = record.getFieldValue(i);
			buf.append("\n" + fieldNames[i] + "=" + field.toString() + " ");
		}
		buf.append("\n");
		return buf.toString();
	}
}
