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

public class ThunkFunctionAdapterV0 extends ThunkFunctionAdapter {

	final static int SCHEMA_VERSION = 0;

	private Table table;

	/**
	 * 
	 * @param dbHandle
	 * @param addrMap
	 * @param create
	 * @throws VersionException
	 * @throws IOException
	 */
	ThunkFunctionAdapterV0(DBHandle dbHandle, AddressMap addrMap, boolean create)
			throws VersionException, IOException {
		super(addrMap);
		if (create) {
			table =
				dbHandle.createTable(THUNK_FUNCTIONS_TABLE_NAME, THUNK_FUNCTION_SCHEMA,
					new int[] { LINKED_FUNCTION_ID_COL });
		}
		else {
			table = dbHandle.getTable(THUNK_FUNCTIONS_TABLE_NAME);
			if (table == null) {
				throw new VersionException(true);
			}
			int version = table.getSchema().getVersion();
			if (version != SCHEMA_VERSION) {
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	@Override
	int getRecordCount() {
		return table.getRecordCount();
	}

	@Override
	RecordIterator iterateThunkRecords() throws IOException {
		return table.iterator();
	}

	@Override
	RecordIterator iterateThunkRecords(long linkedFunctionKey) throws IOException {
		Field field = new LongField(linkedFunctionKey);
		return table.indexIterator(LINKED_FUNCTION_ID_COL, field, field, true);
	}

	@Override
	DBRecord getThunkRecord(long functionKey) throws IOException {
		return table.getRecord(functionKey);
	}

	@Override
	void removeThunkRecord(long functionKey) throws IOException {
		table.deleteRecord(functionKey);
	}

	@Override
	void updateThunkRecord(DBRecord rec) throws IOException {
		table.putRecord(rec);
	}

	@Override
	DBRecord createThunkRecord(long thunkFunctionId, long referencedFunctionId) throws IOException {
		DBRecord rec = THUNK_FUNCTION_SCHEMA.createRecord(thunkFunctionId);
		rec.setField(LINKED_FUNCTION_ID_COL, new LongField(referencedFunctionId));
		table.putRecord(rec);
		return rec;
	}

}
