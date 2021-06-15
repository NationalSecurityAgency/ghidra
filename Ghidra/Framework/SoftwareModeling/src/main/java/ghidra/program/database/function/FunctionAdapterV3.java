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
package ghidra.program.database.function;

import ghidra.program.database.map.AddressMap;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.VersionException;

import java.io.IOException;

import db.*;

class FunctionAdapterV3 extends FunctionAdapter {

	//
	// This version introduces the Return Storage column which will be upgraded by the
	// {@link FunctionManagerDB#programReady(int, int, ghidra.util.task.TaskMonitor)}
	// process. The parameter-offset column has been dropped in favor of using the 
	// calling convention to determine this value.  The following function flags
	// were added:  customer storage flag, signature source type
	//

	final static int SCHEMA_VERSION = 3;

	private Table table;

	/**
	 * 
	 * @param dbHandle
	 * @param addrMap
	 * @param create
	 * @throws VersionException
	 * @throws IOException
	 */
	FunctionAdapterV3(DBHandle dbHandle, AddressMap addrMap, boolean create)
			throws VersionException, IOException {
		super(addrMap);
		if (create) {
			table = dbHandle.createTable(FUNCTIONS_TABLE_NAME, FUNCTION_SCHEMA);
		}
		else {
			table = dbHandle.getTable(FUNCTIONS_TABLE_NAME);
			if (table == null) {
				throw new VersionException("Missing Table: " + FUNCTIONS_TABLE_NAME);
			}
			int version = table.getSchema().getVersion();
			if (version != SCHEMA_VERSION) {
				if (version < SCHEMA_VERSION) {
					throw new VersionException(true);
				}
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	/**
	 * @see ghidra.program.database.function.FunctionAdapter#deleteTable(db.DBHandle)
	 */
	@Override
	protected void deleteTable(DBHandle handle) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.function.FunctionAdapter#getRecordCount()
	 */
	@Override
	int getRecordCount() {
		return table.getRecordCount();
	}

	/**
	 * @see ghidra.program.database.function.FunctionAdapter#removeFunctionRecord(long)
	 */
	@Override
	void removeFunctionRecord(long functionKey) throws IOException {
		table.deleteRecord(functionKey);
	}

	/**
	 * @see ghidra.program.database.function.FunctionAdapter#getFunctionRecord(long)
	 */
	@Override
	DBRecord getFunctionRecord(long functionKey) throws IOException {
		return table.getRecord(functionKey);
	}

	/**
	 * @see ghidra.program.database.function.FunctionAdapter#updateFunctionRecord(db.DBRecord)
	 */
	@Override
	void updateFunctionRecord(DBRecord functionRecord) throws IOException {
		table.putRecord(functionRecord);
	}

	/**
	 * @see ghidra.program.database.function.FunctionAdapter#createFunctionRecord(ghidra.program.model.symbol.Scope, long)
	 */
	@Override
	DBRecord createFunctionRecord(long symbolID, long returnDataTypeId) throws IOException {
		DBRecord rec = FUNCTION_SCHEMA.createRecord(symbolID);
		rec.setByteValue(FUNCTION_FLAGS_COL, getSignatureSourceFlagBits(SourceType.DEFAULT));
		rec.setLongValue(RETURN_DATA_TYPE_ID_COL, returnDataTypeId);
		rec.setByteValue(CALLING_CONVENTION_ID_COL,
			CallingConventionDBAdapter.UNKNOWN_CALLING_CONVENTION_ID);
		rec.setIntValue(STACK_PURGE_COL, Function.UNKNOWN_STACK_DEPTH_CHANGE);
		table.putRecord(rec);
		return rec;
	}

	/**
	 * @see ghidra.program.database.function.FunctionAdapter#iterateFunctionRecords()
	 */
	@Override
	RecordIterator iterateFunctionRecords() throws IOException {
		return table.iterator();
	}

	/**
	 * @see ghidra.program.database.function.FunctionAdapter#translateRecord(db.DBRecord)
	 */
	@Override
	DBRecord translateRecord(DBRecord record) {
		throw new UnsupportedOperationException();
	}

	@Override
	int getVersion() {
		return SCHEMA_VERSION;
	}

}
