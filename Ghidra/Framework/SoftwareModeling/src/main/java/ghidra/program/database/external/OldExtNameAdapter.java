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

class OldExtNameAdapter {

	final static String EXT_NAME_TABLE_NAME = "External Program Names";

	static final Schema EXT_NAME_SCHEMA =
		new Schema(0, "Key", new Field[] { StringField.INSTANCE, StringField.INSTANCE },
			new String[] { "External Name", "External Pathname" });

	static final int EXT_NAME_COL = 0;
	static final int EXT_PATHNAME_COL = 1;

	private Table nameTable;

	/**
	 * Constructor
	 * @param handle handle to the database
	 */
	private OldExtNameAdapter(DBHandle handle) throws VersionException {

		nameTable = handle.getTable(EXT_NAME_TABLE_NAME);
		if (nameTable == null) {
			throw new VersionException("Missing Table: " + EXT_NAME_TABLE_NAME);
		}
		else if (nameTable.getSchema().getVersion() != 0) {
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
	}

	/**
	 * Get iterator over all records
	 * @throws IOException
	 */
	RecordIterator getRecords() throws IOException {
		return nameTable.iterator();
	}

	/**
	 * Returns record count
	 */
	int getRecordCount() {
		return nameTable.getRecordCount();
	}

	private void moveTable(DBHandle handle, TaskMonitor monitor)
			throws IOException, CancelledException {

		DBHandle tmpHandle = handle.getScratchPad();
		Table newRefTable = tmpHandle.createTable(EXT_NAME_TABLE_NAME, EXT_NAME_SCHEMA);

		monitor.setMessage("Processing Old External Names...");
		monitor.initialize(nameTable.getRecordCount());
		int count = 0;

		RecordIterator iter = nameTable.iterator();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			newRefTable.putRecord(iter.next());
			monitor.setProgress(++count);
		}
		handle.deleteTable(EXT_NAME_TABLE_NAME);
		nameTable = newRefTable;
	}

	static OldExtNameAdapter getAdapter(DBHandle dbHandle, int openMode, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {

		OldExtNameAdapter adapter = new OldExtNameAdapter(dbHandle);
		if (openMode == DBConstants.UPGRADE) {
			adapter.moveTable(dbHandle, monitor);
		}
		return adapter;
	}

}
