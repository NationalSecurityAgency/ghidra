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

import java.io.IOException;

import db.*;
import ghidra.program.database.map.AddressMap;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

abstract class ThunkFunctionAdapter {

	static final String THUNK_FUNCTIONS_TABLE_NAME = "Thunk Functions";

	static final int CURRENT_VERSION = ThunkFunctionAdapterV0.SCHEMA_VERSION;

	static final int LINKED_FUNCTION_ID_COL = 0;

	final static Schema THUNK_FUNCTION_SCHEMA = new Schema(CURRENT_VERSION, "ID",
		new Field[] { LongField.INSTANCE }, new String[] { "Linked Function ID" });

	protected AddressMap addrMap;

	static ThunkFunctionAdapter getAdapter(DBHandle handle, int openMode, AddressMap map,
			TaskMonitor monitor) throws VersionException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new ThunkFunctionAdapterV0(handle, map, true);
		}
		try {
			return new ThunkFunctionAdapterV0(handle, map, false);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			ThunkFunctionAdapter adapter = findReadOnlyAdapter(handle, map);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter, map, monitor);
			}
			return adapter;
		}
	}

	ThunkFunctionAdapter(AddressMap map) {
		addrMap = map;
	}

	static ThunkFunctionAdapter findReadOnlyAdapter(DBHandle handle, AddressMap map) {
		return null;
	}

	static ThunkFunctionAdapter upgrade(DBHandle handle, ThunkFunctionAdapter oldAdapter,
			AddressMap map, TaskMonitor monitor) throws VersionException, IOException {
		return new ThunkFunctionAdapterV0(handle, map, true);
	}

	abstract int getRecordCount();

	abstract RecordIterator iterateThunkRecords() throws IOException;

	abstract RecordIterator iterateThunkRecords(long linkedFunctionKey) throws IOException;

	abstract DBRecord getThunkRecord(long functionKey) throws IOException;

	abstract void removeThunkRecord(long functionKey) throws IOException;

	abstract void updateThunkRecord(DBRecord rec) throws IOException;

	abstract DBRecord createThunkRecord(long thunkFunctionId, long referencedFunctionId)
			throws IOException;

}
