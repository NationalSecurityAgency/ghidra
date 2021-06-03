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
package ghidra.program.database.oldfunction;

import java.io.IOException;

import db.*;
import ghidra.program.database.map.AddressMap;
import ghidra.util.exception.VersionException;

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
		new Field[] { LongField.INSTANCE, StringField.INSTANCE, LongField.INSTANCE,
			StringField.INSTANCE, StringField.INSTANCE },
		new String[] { "Function ID", "Register", "DataType ID", "Name", "Comment" });

	private Table table;

	OldRegisterVariableDBAdapterV0(DBHandle dbHandle, AddressMap addrMap) throws VersionException {
		table = dbHandle.getTable(REG_PARMS_TABLE_NAME);
		if (table == null || table.getSchema().getVersion() != 0) {
			throw new VersionException(false);
		}
	}

	@Override
	public DBRecord getRegisterVariableRecord(long key) throws IOException {
		return table.getRecord(key);
	}

	@Override
	public Field[] getRegisterVariableKeys(long functionKey) throws IOException {
		return table.findRecords(new LongField(functionKey),
			OldStackVariableDBAdapter.STACK_VAR_FUNCTION_KEY_COL);
	}

	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(REG_PARMS_TABLE_NAME);
	}

	@Override
	int getRecordCount() {
		return table.getRecordCount();
	}
}
