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
package ghidra.program.database.data;

import java.io.IOException;

import db.*;
import ghidra.util.exception.VersionException;

/**
 * Version 0 implementation for accessing the Component database table. 
 */
class ComponentDBAdapterV0 extends ComponentDBAdapter {

	static final int VERSION = 0;

	static final int V0_COMPONENT_PARENT_ID_COL = 0;
	static final int V0_COMPONENT_OFFSET_COL = 1;
	static final int V0_COMPONENT_DT_ID_COL = 2;
	static final int V0_COMPONENT_FIELD_NAME_COL = 3;
	static final int V0_COMPONENT_COMMENT_COL = 4;
	static final int V0_COMPONENT_SIZE_COL = 5;
	static final int V0_COMPONENT_ORDINAL_COL = 6;

	static final Schema V0_COMPONENT_SCHEMA = new Schema(0, "Data Type ID",
		new Field[] { LongField.INSTANCE, IntField.INSTANCE, LongField.INSTANCE,
			StringField.INSTANCE, StringField.INSTANCE, IntField.INSTANCE, IntField.INSTANCE },
		new String[] { "Parent", "Offset", "Data Type ID", "Field Name", "Comment",
			"Component Size", "Ordinal" });

	private Table componentTable;

	/**
	 * Gets a version 0 adapter for the Component database table.
	 * @param handle handle to the database containing the table.
	 * @param tablePrefix prefix to be used with default table name
	 * @param create true if this constructor should create the table.
	 * @throws VersionException if the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if an IO error occurs
	 */
	ComponentDBAdapterV0(DBHandle handle, String tablePrefix, boolean create)
			throws VersionException, IOException {
		String tableName = tablePrefix + COMPONENT_TABLE_NAME;
		if (create) {
			componentTable = handle.createTable(tableName, V0_COMPONENT_SCHEMA,
				new int[] { V0_COMPONENT_PARENT_ID_COL });
		}
		else {
			componentTable = handle.getTable(tableName);
			if (componentTable == null) {
				throw new VersionException("Missing Table: " + tableName);
			}
			if (componentTable.getSchema().getVersion() != VERSION) {
				throw new VersionException(false);
			}
		}
	}

	@Override
	DBRecord createRecord(long dataTypeID, long parentID, int length, int ordinal, int offset,
			String name, String comment) throws IOException {
		long key =
			DataTypeManagerDB.createKey(DataTypeManagerDB.COMPONENT, componentTable.getKey());
		DBRecord record = ComponentDBAdapter.COMPONENT_SCHEMA.createRecord(key);
		record.setLongValue(ComponentDBAdapter.COMPONENT_PARENT_ID_COL, parentID);
		record.setLongValue(ComponentDBAdapter.COMPONENT_OFFSET_COL, offset);
		record.setLongValue(ComponentDBAdapter.COMPONENT_DT_ID_COL, dataTypeID);
		record.setString(ComponentDBAdapter.COMPONENT_FIELD_NAME_COL, name);
		record.setString(ComponentDBAdapter.COMPONENT_COMMENT_COL, comment);
		record.setIntValue(ComponentDBAdapter.COMPONENT_SIZE_COL, length);
		record.setIntValue(ComponentDBAdapter.COMPONENT_ORDINAL_COL, ordinal);
		componentTable.putRecord(record);
		return record;
	}

	@Override
	DBRecord getRecord(long componentID) throws IOException {
		return componentTable.getRecord(componentID);
	}

	@Override
	void updateRecord(DBRecord record) throws IOException {
		componentTable.putRecord(record);
	}

	@Override
	boolean removeRecord(long componentID) throws IOException {
		return componentTable.deleteRecord(componentID);
	}

	@Override
	Field[] getComponentIdsInComposite(long compositeID) throws IOException {
		return componentTable.findRecords(new LongField(compositeID),
			ComponentDBAdapter.COMPONENT_PARENT_ID_COL);
	}

}
