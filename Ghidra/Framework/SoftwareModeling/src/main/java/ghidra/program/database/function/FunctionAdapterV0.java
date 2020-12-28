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
import ghidra.util.exception.VersionException;

import java.io.IOException;

import db.*;

class FunctionAdapterV0 extends FunctionAdapter {

	final static int SCHEMA_VERSION = 0;

	// NOTE: The following commented out declarations are hereto indicate this version's schema.

	private static final int V0_RETURN_DATA_TYPE_ID_COL = 0;
	private static final int V0_STACK_PURGE_COL = 1;
	private static final int V0_STACK_PARAM_OFFSET_COL = 2;
	private static final int V0_STACK_RETURN_OFFSET_COL = 3;  // CHANGE: Encoded Register or Stack Address
	private static final int V0_STACK_LOCAL_SIZE_COL = 4;

//	final static Schema FUNCTION_SCHEMA = new Schema(SCHEMA_VERSION,
//			"ID",
//			new Class [] {
//						LongField.class, 
//						IntField.class,
//						IntField.class,
//						IntField.class, 
//						IntField.class,
//			},
//			new String [] {
//						"Return DataType ID", 
//						"StackPurge", 
//						"StackParamOffset", 
//						"StackReturnOffset", 
//						"StackLocalSize"
//						}
//			);

	private Table table;

	/**
	 * 
	 * @param dbHandle
	 * @param addrMap
	 * @param create
	 * @throws VersionException
	 * @throws IOException
	 */
	FunctionAdapterV0(DBHandle dbHandle, AddressMap addrMap) throws VersionException, IOException {
		super(addrMap);
		table = dbHandle.getTable(FUNCTIONS_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + FUNCTIONS_TABLE_NAME);
		}
		else if (table.getSchema().getVersion() != SCHEMA_VERSION) {
			throw new VersionException(false);
		}
	}

	/**
	 * @see ghidra.program.database.function.FunctionAdapter#deleteTable(db.DBHandle)
	 */
	@Override
	protected void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(FUNCTIONS_TABLE_NAME);
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
//		table.deleteRecord(functionKey);
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.function.FunctionAdapter#getFunctionRecord(long)
	 */
	@Override
	DBRecord getFunctionRecord(long functionKey) throws IOException {
		DBRecord oldRecord = table.getRecord(functionKey);
		return translateRecord(oldRecord);
	}

	/**
	 * @see ghidra.program.database.function.FunctionAdapter#updateFunctionRecord(db.DBRecord)
	 */
	@Override
	void updateFunctionRecord(DBRecord functionRecord) throws IOException {
//		table.putRecord(functionRecord);
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.function.FunctionAdapter#createFunctionRecord(ghidra.program.model.symbol.Scope, long)
	 */
	@Override
	DBRecord createFunctionRecord(long symbolID, long returnDataTypeId) throws IOException {
//		Record rec = FUNCTION_SCHEMA.createRecord(symbolID);
//		rec.setLongValue(RETURN_DATA_TYPE_ID_COL, returnDataTypeId);
//		rec.setIntValue(STACK_PURGE_COL, Function.UNKNOWN_STACK_DEPTH_CHANGE);
//		table.putRecord(rec);
//		return rec;
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.function.FunctionAdapter#iterateFunctionRecords()
	 */
	@Override
	RecordIterator iterateFunctionRecords() throws IOException {
		return new TranslatedRecordIterator(table.iterator());
	}

	/**
	 * @see ghidra.program.database.function.FunctionAdapter#translateRecord(db.DBRecord)
	 */
	@Override
	DBRecord translateRecord(DBRecord record) {
		if (record == null) {
			return null;
		}
		long entryPointKey = record.getKey();
		DBRecord newRecord = FunctionAdapter.FUNCTION_SCHEMA.createRecord(entryPointKey);
		newRecord.setLongValue(FunctionAdapter.RETURN_DATA_TYPE_ID_COL,
			record.getLongValue(V0_RETURN_DATA_TYPE_ID_COL));
		newRecord.setIntValue(FunctionAdapter.STACK_PURGE_COL,
			record.getIntValue(V0_STACK_PURGE_COL));
//		newRecord.setIntValue(FunctionAdapter.STACK_PARAM_OFFSET_COL,
//			record.getIntValue(V0_STACK_PARAM_OFFSET_COL));
		newRecord.setIntValue(FunctionAdapter.STACK_RETURN_OFFSET_COL,
			record.getIntValue(V0_STACK_RETURN_OFFSET_COL));
		newRecord.setIntValue(FunctionAdapter.STACK_LOCAL_SIZE_COL,
			record.getIntValue(V0_STACK_LOCAL_SIZE_COL));
		newRecord.setByteValue(FunctionAdapter.FUNCTION_FLAGS_COL,
			FunctionAdapter.FUNCTION_CUSTOM_PARAM_STORAGE_FLAG);
		newRecord.setByteValue(FunctionAdapter.CALLING_CONVENTION_ID_COL, (byte) 0);
		newRecord.setString(FunctionAdapter.RETURN_STORAGE_COL, null);
		return newRecord;
	}

	@Override
	int getVersion() {
		return SCHEMA_VERSION;
	}

}
