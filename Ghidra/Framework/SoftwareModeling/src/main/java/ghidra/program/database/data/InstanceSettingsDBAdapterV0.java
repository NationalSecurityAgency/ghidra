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
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * 
 */
class InstanceSettingsDBAdapterV0 extends InstanceSettingsDBAdapter {

	// Instance Settings Columns
	static final int V0_INST_ADDR_COL = 0;
	static final int V0_INST_NAME_COL = 1;
	static final int V0_INST_LONG_VALUE_COL = 2;
	static final int V0_INST_STRING_VALUE_COL = 3;
	static final int V0_INST_BYTE_VALUE_COL = 4;

	static final Schema V0_INSTANCE_SCHEMA = new Schema(0, "Settings ID",
		new Field[] { LongField.INSTANCE, StringField.INSTANCE, LongField.INSTANCE,
			StringField.INSTANCE, BinaryField.INSTANCE },
		new String[] { "Address", "Settings Name", "Long Value", "String Value", "Byte Value" });

	private Table instanceTable;

	/**
	 * Constructor
	 * 
	 */
	InstanceSettingsDBAdapterV0(DBHandle handle, boolean create)
			throws VersionException, IOException {

		if (create) {
			instanceTable = handle.createTable(INSTANCE_TABLE_NAME, V0_INSTANCE_SCHEMA,
				new int[] { V0_INST_ADDR_COL });
		}
		else {
			instanceTable = handle.getTable(INSTANCE_TABLE_NAME);
			if (instanceTable == null) {
				throw new VersionException("Missing Table: " + INSTANCE_TABLE_NAME);
			}
			if (instanceTable.getSchema().getVersion() != 0) {
				throw new VersionException("Expected version 0 for table " + INSTANCE_TABLE_NAME +
					" but got " + instanceTable.getSchema().getVersion());
			}
		}
	}

	@Override
	public DBRecord createInstanceRecord(long addr, String name, String strValue, long longValue,
			byte[] byteValue) throws IOException {

		DBRecord record = V0_INSTANCE_SCHEMA.createRecord(instanceTable.getKey());
		record.setLongValue(V0_INST_ADDR_COL, addr);
		record.setString(V0_INST_NAME_COL, name);
		record.setString(V0_INST_STRING_VALUE_COL, strValue);
		record.setLongValue(V0_INST_LONG_VALUE_COL, longValue);
		record.setBinaryData(V0_INST_BYTE_VALUE_COL, byteValue);
		instanceTable.putRecord(record);
		return record;
	}

	@Override
	public Field[] getInstanceKeys(long addr) throws IOException {
		return instanceTable.findRecords(new LongField(addr), V0_INST_ADDR_COL);
	}

	@Override
	public boolean removeInstanceRecord(long settingsID) throws IOException {
		return instanceTable.deleteRecord(settingsID);
	}

	@Override
	public DBRecord getInstanceRecord(long settingsID) throws IOException {
		return instanceTable.getRecord(settingsID);
	}

	@Override
	public void updateInstanceRecord(DBRecord record) throws IOException {
		instanceTable.putRecord(record);
	}

	@Override
	public RecordIterator getRecords(long start, long end) throws IOException {

		return instanceTable.indexIterator(V0_INST_ADDR_COL, new LongField(start),
			new LongField(end), true);
	}

	@Override
	RecordIterator getRecords() throws IOException {
		return instanceTable.iterator();
	}

	@Override
	int getRecordCount() {
		return instanceTable.getRecordCount();
	}

	@Override
	void delete(long start, long end, TaskMonitor monitor) throws CancelledException, IOException {
		DBFieldIterator it = instanceTable.indexKeyIterator(V0_INST_ADDR_COL, new LongField(start),
			new LongField(end), true);
		while (it.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			instanceTable.deleteRecord(it.next());
		}
	}
}
