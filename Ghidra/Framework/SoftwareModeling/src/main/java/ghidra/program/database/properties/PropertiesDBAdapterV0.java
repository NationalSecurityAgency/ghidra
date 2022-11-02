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

import java.io.IOException;

import db.*;
import ghidra.util.exception.VersionException;

class PropertiesDBAdapterV0 implements PropertiesDBAdapter {

	private Table propertiesTable;

	/**
	 * Construct property map DB adapter
	 * @param dbHandle database handle
	 * @throws VersionException if version error occurs
	 */
	public PropertiesDBAdapterV0(DBHandle dbHandle) throws VersionException {
		propertiesTable = dbHandle.getTable(DBPropertyMapManager.PROPERTIES_TABLE_NAME);
		testVersion(0);
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return propertiesTable.iterator();
	}

	@Override
	public void putRecord(String propertyName, byte type, String objClassName) throws IOException {
		DBRecord rec =
			DBPropertyMapManager.PROPERTIES_SCHEMA.createRecord(new StringField(propertyName));
		rec.setByteValue(DBPropertyMapManager.PROPERTY_TYPE_COL, type);
		if (type == DBPropertyMapManager.OBJECT_PROPERTY_TYPE) {
			rec.setString(DBPropertyMapManager.OBJECT_CLASS_COL, objClassName);
		}

		propertiesTable.putRecord(rec);
	}

	@Override
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
