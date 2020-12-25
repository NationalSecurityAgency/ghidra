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
package ghidra.program.database.references;

import java.io.IOException;

import db.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter for the stack references table in the database. 
 */
class OldStackRefDBAdpater {

	static final String STACK_REF_TABLE_NAME = "Stack References";

	static final Schema STACK_REF_SCHEMA = new Schema(0, "Key",
		new Field[] { LongField.INSTANCE, ShortField.INSTANCE, BooleanField.INSTANCE,
			ShortField.INSTANCE },
		new String[] { "From Address", "Op Index", "User Defined", "Stack Offset" });

	static final int FROM_ADDR_COL = 0;
	static final int OP_INDEX_COL = 1;
	static final int USER_DEFINED_COL = 2;
	static final int STACK_OFFSET_COL = 3;

	private Table refTable;

	/**
	 * Constructor
	 * @param handle handle to the database
	 */
	private OldStackRefDBAdpater(DBHandle handle) throws VersionException {

		refTable = handle.getTable(STACK_REF_TABLE_NAME);
		if (refTable == null) {
			throw new VersionException("Missing Table: " + STACK_REF_TABLE_NAME);
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
		Table newRefTable = tmpHandle.createTable(STACK_REF_TABLE_NAME, STACK_REF_SCHEMA);

		monitor.setMessage("Processing Old Stack References...");
		monitor.initialize(refTable.getRecordCount());
		int count = 0;

		RecordIterator iter = refTable.iterator();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			newRefTable.putRecord(iter.next());
			monitor.setProgress(++count);
		}
		handle.deleteTable(STACK_REF_TABLE_NAME);
		refTable = newRefTable;
	}

	static OldStackRefDBAdpater getAdapter(DBHandle dbHandle, int openMode, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {

		OldStackRefDBAdpater adapter = new OldStackRefDBAdpater(dbHandle);
		if (openMode == DBConstants.UPGRADE) {
			adapter.moveTable(dbHandle, monitor);
		}
		return adapter;
	}
}
