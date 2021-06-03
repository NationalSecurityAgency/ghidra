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
package ghidra.program.database.external;

import java.io.IOException;

import db.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

class OldExtRefAdapter {

	static final String EXT_REF_TABLE_NAME = "External References";

	static final Schema EXT_REF_SCHEMA = new Schema(0, "Key",
		new Field[] { LongField.INSTANCE, ShortField.INSTANCE, BooleanField.INSTANCE,
			LongField.INSTANCE, StringField.INSTANCE, LongField.INSTANCE, BooleanField.INSTANCE },
		new String[] { "From Address", "Op Index", "User Defined", "External Name ID", "Label",
			"External To", "External To Exists" });

	static final int FROM_ADDR_COL = 0;
	static final int OP_INDEX_COL = 1;
	static final int USER_DEFINED_COL = 2;
	static final int EXT_NAME_ID_COL = 3;
	static final int LABEL_COL = 4;
	static final int EXT_TO_ADDR_COL = 5;
	static final int EXT_ADDR_EXISTS_COL = 6;

	private Table refTable;

	/**
	 * Constructor
	 * @param handle handle to the database
	 */
	private OldExtRefAdapter(DBHandle handle) throws VersionException {

		refTable = handle.getTable(EXT_REF_TABLE_NAME);
		if (refTable == null) {
			throw new VersionException("Missing Table: " + EXT_REF_TABLE_NAME);
		}
		else if (refTable.getSchema().getVersion() != 0) {
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
	}

	/**
	 * Get iterator over all records
	 * @throws IOException
	 */
	RecordIterator getRecords() throws IOException {
		return refTable.iterator();
	}

	/**
	 * Returns record count
	 */
	int getRecordCount() {
		return refTable.getRecordCount();
	}

	private void moveTable(DBHandle handle, TaskMonitor monitor)
			throws IOException, CancelledException {

		DBHandle tmpHandle = handle.getScratchPad();
		Table newRefTable = tmpHandle.createTable(EXT_REF_TABLE_NAME, EXT_REF_SCHEMA);

		monitor.setMessage("Processing Old External References...");
		monitor.initialize(refTable.getRecordCount());
		int count = 0;

		RecordIterator iter = refTable.iterator();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			newRefTable.putRecord(iter.next());
			monitor.setProgress(++count);
		}
		handle.deleteTable(EXT_REF_TABLE_NAME);
		refTable = newRefTable;
	}

	static OldExtRefAdapter getAdapter(DBHandle dbHandle, int openMode, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {

		OldExtRefAdapter adapter = new OldExtRefAdapter(dbHandle);
		if (openMode == DBConstants.UPGRADE) {
			adapter.moveTable(dbHandle, monitor);
		}
		return adapter;
	}
}
