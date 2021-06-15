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
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 *
 * Adapter to access the Array database table for array data types. 
 * 
 */
abstract class ArrayDBAdapter {
	static final Schema SCHEMA = ArrayDBAdapterV1.V1_SCHEMA;
	static final int ARRAY_DT_ID_COL = ArrayDBAdapterV1.V1_ARRAY_DT_ID_COL;
	static final int ARRAY_DIM_COL = ArrayDBAdapterV1.V1_ARRAY_DIM_COL;
	static final int ARRAY_LENGTH_COL = ArrayDBAdapterV1.V1_ARRAY_LENGTH_COL;
	static final int ARRAY_CAT_COL = ArrayDBAdapterV1.V1_ARRAY_CAT_COL;

	static ArrayDBAdapter getAdapter(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, IOException {
		if (openMode == DBConstants.CREATE) {
			return new ArrayDBAdapterV1(handle, true);
		}
		try {
			return new ArrayDBAdapterV1(handle, false);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			ArrayDBAdapter adapter = findReadOnlyAdapter(handle);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter);
			}
			return adapter;
		}
	}

	static ArrayDBAdapter findReadOnlyAdapter(DBHandle handle) throws VersionException {
		return new ArrayDBAdapterV0(handle);
	}

	static ArrayDBAdapter upgrade(DBHandle handle, ArrayDBAdapter oldAdapter)
			throws VersionException, IOException {

		DBHandle tmpHandle = new DBHandle();
		long id = tmpHandle.startTransaction();
		ArrayDBAdapter tmpAdapter = null;
		try {
			tmpAdapter = new ArrayDBAdapterV1(tmpHandle, true);
			RecordIterator it = oldAdapter.getRecords();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				tmpAdapter.updateRecord(rec);
			}
			oldAdapter.deleteTable(handle);
			ArrayDBAdapterV1 newAdapter = new ArrayDBAdapterV1(handle, true);
			it = tmpAdapter.getRecords();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				newAdapter.updateRecord(rec);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.endTransaction(id, true);
			tmpHandle.close();
		}
	}

	abstract DBRecord createRecord(long dataTypeID, int numberOfElements, int length, long catID)
			throws IOException;

	abstract DBRecord getRecord(long arrayID) throws IOException;

	abstract RecordIterator getRecords() throws IOException;

	abstract boolean removeRecord(long dataID) throws IOException;

	abstract void updateRecord(DBRecord record) throws IOException;

	abstract void deleteTable(DBHandle handle) throws IOException;

	abstract Field[] getRecordIdsInCategory(long categoryID) throws IOException;

}
