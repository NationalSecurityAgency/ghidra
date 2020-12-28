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
class OldFunctionDBAdapterV1 extends OldFunctionDBAdapter {

	static final String FUNCTIONS_TABLE_NAME = "Functions";

	final static int SCHEMA_VERSION = 1;

	static final int V1_RETURN_DATA_TYPE_ID_COL = 0;
	static final int V1_STACK_DEPTH_COL = 1;
	static final int V1_STACK_PARAM_OFFSET_COL = 2;
	static final int V1_STACK_RETURN_OFFSET_COL = 3;
	static final int V1_STACK_LOCAL_SIZE_COL = 4;
	static final int V1_REPEATABLE_COMMENT_COL = 5;

	final static Schema V1_FUNCTIONS_SCHEMA = new Schema(SCHEMA_VERSION, "Entry Point",
		new Field[] { LongField.INSTANCE, IntField.INSTANCE, IntField.INSTANCE, IntField.INSTANCE,
			IntField.INSTANCE, StringField.INSTANCE },
		new String[] { "Return DataType ID", "StackDepth", "StackParamOffset", "StackReturnOffset",
			"StackLocalSize", "RepeatableComment" });
	protected Table table;

	OldFunctionDBAdapterV1(DBHandle dbHandle, AddressMap addrMap) throws VersionException {
		super(addrMap);
		table = dbHandle.getTable(FUNCTIONS_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + FUNCTIONS_TABLE_NAME);
		}
		else if (table.getSchema().getVersion() != SCHEMA_VERSION) {
			int version = table.getSchema().getVersion();
			if (version < SCHEMA_VERSION) {
				throw new VersionException(true);
			}
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
	}

	/**
	 * @see ghidra.program.database.function.FunctionDBAdapter#getFunctionRecord(long)
	 */
	@Override
	public DBRecord getFunctionRecord(long functionKey) throws IOException {
		return table.getRecord(functionKey);
	}

	/**
	 * @see ghidra.program.database.function.FunctionDBAdapter#iterateFunctionRecords()
	 */
	@Override
	public RecordIterator iterateFunctionRecords() throws IOException {
		return table.iterator();
	}

	/**
	 * @see ghidra.program.database.function.FunctionDBAdapter#translateRecord(ghidra.framework.store.db.DBRecord)
	 */
	public DBRecord translateRecord(DBRecord oldRecord) {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.function.FunctionDBAdapter#getFunctionRecordCount()
	 */
	@Override
	public int getRecordCount() {
		return table.getRecordCount();
	}

	/**
	 * @see ghidra.program.database.function.FunctionDBAdapter#deleteTable(ghidra.framework.store.db.DBHandle)
	 */
	@Override
	protected void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(FUNCTIONS_TABLE_NAME);
	}

}
