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
package ghidra.program.database.oldfunction;

import ghidra.program.database.map.AddressMap;
import ghidra.util.exception.VersionException;

import java.io.IOException;

import db.*;

/**
 * 
 * 
 */
class OldRegisterVariableDBAdapterV0 extends OldRegisterVariableDBAdapter {
	final static int SCHEMA_VERSION = 0;

	// Register Variables Table Columns
	static final int V0_REG_VAR_FUNCTION_KEY_COL = 0;
	static final int V0_REG_VAR_REGNAME_COL = 1;
	static final int V0_REG_VAR_DATA_TYPE_ID_COL = 2;
	static final int V0_REG_VAR_NAME_COL = 3;
	static final int V0_REG_VAR_COMMENT_COL = 4;

	static final String REG_PARMS_TABLE_NAME = "Register Parameters";
	static final Schema V0_REG_PARAMS_SCHEMA = new Schema(SCHEMA_VERSION, "Key",
		new Class[] { LongField.class, StringField.class, LongField.class, StringField.class,
			StringField.class }, new String[] { "Function ID", "Register", "DataType ID", "Name",
			"Comment" });

	private Table table;

	OldRegisterVariableDBAdapterV0(DBHandle dbHandle, AddressMap addrMap) throws VersionException {
		table = dbHandle.getTable(REG_PARMS_TABLE_NAME);
		if (table == null || table.getSchema().getVersion() != 0) {
			throw new VersionException(false);
		}
	}

	/**
	 * @see ghidra.program.database.function.FunctionDBAdapter#getRegisterVariableRecord(long)
	 */
	@Override
	public Record getRegisterVariableRecord(long key) throws IOException {
		return table.getRecord(key);
	}

	/**
	 * @see ghidra.program.database.function.FunctionDBAdapter#getRegisterVariableKeys(long)
	 */
	@Override
	public long[] getRegisterVariableKeys(long functionKey) throws IOException {
		return table.findRecords(new LongField(functionKey),
			OldStackVariableDBAdapter.STACK_VAR_FUNCTION_KEY_COL);
	}

	/**
	 * @see ghidra.program.database.function.RegisterVariableDBAdapter#deleteTable(db.DBHandle)
	 */
	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(REG_PARMS_TABLE_NAME);
	}

	/**
	 * @see ghidra.program.database.function.RegisterVariableDBAdapter#getRecordCount()
	 */
	@Override
	int getRecordCount() {
		return table.getRecordCount();
	}
}
