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
 * Database adapter implementation for Functions.
 * Handles three tables: Functions, Stack Variables, and Register Variables.
 */
class OldFunctionDBAdapterV0 extends OldFunctionDBAdapter {
	static final String V0_FUNCTIONS_TABLE_NAME = "Functions";
	static final int V0_RETURN_DATA_TYPE_ID_COL = 0;
	static final int V0_STACK_DEPTH_COL = 1;
	static final int V0_STACK_PARAM_OFFSET_COL = 2;
	static final int V0_STACK_RETURN_OFFSET_COL = 3;
	static final int V0_STACK_LOCAL_SIZE_COL = 4;

//	private final Schema oldFunctionSchema = new Schema(0,
//								"Entry Point",
//								new Class [] {
//											LongField.class, 
//											IntField.class,
//											IntField.class,
//											IntField.class, 
//											IntField.class},
//								new String [] {
//											"Return DataType ID", 
//											"StackDepth", 
//											"StackParamOffset", 
//											"StackReturnOffset", 
//											"StackLocalSize"}
//
//	);

	protected Table table;

	OldFunctionDBAdapterV0(DBHandle dbHandle, AddressMap addrMap) throws VersionException {
		super(addrMap);

		table = dbHandle.getTable(V0_FUNCTIONS_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + V0_FUNCTIONS_TABLE_NAME);
		}
		else if (table.getSchema().getVersion() != 0) {
			throw new VersionException("Expected version 0 for table " + V0_FUNCTIONS_TABLE_NAME +
				" but got " + table.getSchema().getVersion());
		}
	}

	/**
	 * @see ghidra.program.database.function.FunctionDBAdapter#getFunctionRecord(long)
	 */
	@Override
	public Record getFunctionRecord(long functionKey) throws IOException {
		Record oldRecord = table.getRecord(functionKey);
		return translateRecord(oldRecord);
	}

	/**
	 * @see ghidra.program.database.function.FunctionDBAdapter#translateRecord(ghidra.framework.store.db.Record)
	 */
	public Record translateRecord(Record oldRecord) {
		if (oldRecord == null) {
			return null;
		}
		long entryPointKey = oldRecord.getKey();
		Record newRecord = OldFunctionDBAdapter.FUNCTIONS_SCHEMA.createRecord(entryPointKey);
		newRecord.setLongValue(OldFunctionDBAdapter.RETURN_DATA_TYPE_ID_COL,
			oldRecord.getLongValue(V0_RETURN_DATA_TYPE_ID_COL));
		newRecord.setIntValue(OldFunctionDBAdapter.STACK_DEPTH_COL,
			oldRecord.getIntValue(V0_STACK_DEPTH_COL));
		newRecord.setIntValue(OldFunctionDBAdapter.STACK_PARAM_OFFSET_COL,
			oldRecord.getIntValue(V0_STACK_PARAM_OFFSET_COL));
		newRecord.setIntValue(OldFunctionDBAdapter.STACK_RETURN_OFFSET_COL,
			oldRecord.getIntValue(V0_STACK_RETURN_OFFSET_COL));
		newRecord.setIntValue(OldFunctionDBAdapter.STACK_LOCAL_SIZE_COL,
			oldRecord.getIntValue(V0_STACK_LOCAL_SIZE_COL));
		newRecord.setString(OldFunctionDBAdapter.REPEATABLE_COMMENT_COL, "");
		return newRecord;
	}

	/**
	 * @see ghidra.program.database.function.FunctionDBAdapter#iterateFunctionRecords()
	 */
	@Override
	public RecordIterator iterateFunctionRecords() throws IOException {
		return new TranslatedRecordIterator(table.iterator());
	}

	class TranslatedRecordIterator implements RecordIterator {
		private RecordIterator it;

		TranslatedRecordIterator(RecordIterator it) {
			this.it = it;
		}

		public boolean delete() throws IOException {
			throw new UnsupportedOperationException();
		}

		public boolean hasNext() throws IOException {
			return it.hasNext();
		}

		public boolean hasPrevious() throws IOException {
			return it.hasPrevious();
		}

		public Record next() throws IOException {
			Record rec = it.next();
			return translate(rec);
		}

		public Record previous() throws IOException {
			Record rec = it.previous();
			return translate(rec);
		}

		private Record translate(Record oldRecord) {
			return translateRecord(oldRecord);
		}
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
		handle.deleteTable(V0_FUNCTIONS_TABLE_NAME);
	}

}
