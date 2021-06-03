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

import ghidra.util.exception.VersionException;

import java.io.IOException;

import db.*;

class PropertiesDBAdapterV0 implements PropertiesDBAdapter {

	private Table propertiesTable;

	/**
	 * @param dbHandle
	 */
	public PropertiesDBAdapterV0(DBHandle dbHandle) throws VersionException {
		propertiesTable = dbHandle.getTable(DBPropertyMapManager.PROPERTIES_TABLE_NAME);
		testVersion(0);
	}

	/**
	 * @see ghidra.program.database.properties.PropertiesDBAdapter#iterator()
	 */
	public RecordIterator getRecords() throws IOException {
		return propertiesTable.iterator();
	}

	/**
	 * @see ghidra.program.database.properties.PropertiesDBAdapter#createRecord(java.lang.String, byte, java.lang.String)
	 */
	public void putRecord(String propertyName, byte type, String objClassName) throws IOException {
		DBRecord rec =
			DBPropertyMapManager.PROPERTIES_SCHEMA.createRecord(new StringField(propertyName));
		rec.setByteValue(DBPropertyMapManager.PROPERTY_TYPE_COL, type);
		if (type == DBPropertyMapManager.OBJECT_PROPERTY_TYPE) {
			rec.setString(DBPropertyMapManager.OBJECT_CLASS_COL, objClassName);
		}

		propertiesTable.putRecord(rec);
	}

	/**
	 * @see ghidra.program.database.properties.PropertiesDBAdapter#removeRecord(java.lang.String)
	 */
	public void removeRecord(String propertyName) throws IOException {
		propertiesTable.deleteRecord(new StringField(propertyName));
	}

	/**
	 * Test the version on the Properties table
	 * @param expectedVersion expected version
	 * @throws VersionException if the expected version is not the
	 * same version as that of the table
	 */
	private void testVersion(int expectedVersion) throws VersionException {

		if (propertiesTable == null) {
			throw new VersionException("Properties table not found");
		}
		int versionNumber = propertiesTable.getSchema().getVersion();
		if (versionNumber != expectedVersion) {
			throw new VersionException("Properties table: Expected Version " + expectedVersion +
				", got " + versionNumber);
		}
	}

}
