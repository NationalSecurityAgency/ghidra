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
class OldStackVariableDBAdapterV0 extends OldStackVariableDBAdapter {

	static final String STACK_VARS_TABLE_NAME = "Stack Variables";

	final static int SCHEMA_VERSION = 0;

	// Stack Variables Table Columns
	static final int V0_STACK_VAR_FUNCTION_KEY_COL = 0;
	static final int V0_STACK_VAR_OFFSET_COL = 1;
	static final int V0_STACK_VAR_DATA_TYPE_ID_COL = 2;
	static final int V0_STACK_VAR_NAME_COL = 3;
	static final int V0_STACK_VAR_COMMENT_COL = 4;

	static final Schema V0_STACK_VARS_SCHEMA = new Schema(SCHEMA_VERSION, "Key",
		new Field[] { LongField.INSTANCE, IntField.INSTANCE, LongField.INSTANCE,
			StringField.INSTANCE, StringField.INSTANCE },
		new String[] { "Function ID", "Offset", "DataType ID", "Name", "Comment" });

	private Table table;

	OldStackVariableDBAdapterV0(DBHandle dbHandle, AddressMap addrMap) throws VersionException {

		table = dbHandle.getTable(STACK_VARS_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + STACK_VARS_TABLE_NAME);
		}
		else if (table.getSchema().getVersion() != 0) {
			throw new VersionException("Expected version 0 for table " + STACK_VARS_TABLE_NAME +
				" but got " + table.getSchema().getVersion());
		}
	}

	@Override
	public DBRecord getStackVariableRecord(long key) throws IOException {
		return translateRecord(table.getRecord(key));
	}

	@Override
	public Field[] getStackVariableKeys(long functionKey) throws IOException {
		return table.findRecords(new LongField(functionKey), V0_STACK_VAR_FUNCTION_KEY_COL);
	}

	private DBRecord translateRecord(DBRecord oldRec) {
		if (oldRec == null) {
			return null;
		}
		DBRecord rec = OldStackVariableDBAdapter.STACK_VARS_SCHEMA.createRecord(oldRec.getKey());

		rec.setLongValue(OldStackVariableDBAdapter.STACK_VAR_FUNCTION_KEY_COL,
			oldRec.getLongValue(V0_STACK_VAR_FUNCTION_KEY_COL));
		rec.setString(OldStackVariableDBAdapter.STACK_VAR_NAME_COL,
			oldRec.getString(V0_STACK_VAR_NAME_COL));
		rec.setLongValue(OldStackVariableDBAdapter.STACK_VAR_DATA_TYPE_ID_COL,
			oldRec.getLongValue(V0_STACK_VAR_DATA_TYPE_ID_COL));
		rec.setIntValue(OldStackVariableDBAdapter.STACK_VAR_OFFSET_COL,
			oldRec.getIntValue(V0_STACK_VAR_OFFSET_COL));
		rec.setString(OldStackVariableDBAdapter.STACK_VAR_COMMENT_COL,
			oldRec.getString(V0_STACK_VAR_COMMENT_COL));
		rec.setIntValue(OldStackVariableDBAdapter.STACK_VAR_DT_LENGTH_COL, 1);
		return rec;
	}

	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(STACK_VARS_TABLE_NAME);
	}

}
