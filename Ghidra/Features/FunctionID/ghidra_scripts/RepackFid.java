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
// Repack FID database file to eliminate unused blocks and possibly make indices more efficient
//@category FunctionID
import java.io.File;
import java.io.IOException;

import db.DBHandle;
import db.DBRecord;
import db.RecordIterator;
import db.Schema;
import db.Table;
import ghidra.app.script.GhidraScript;
import ghidra.framework.store.db.PackedDBHandle;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public class RepackFid extends GhidraScript {

	/**
	 * Copy a single table between databases
	 * @param oldTable is the old table to copy
	 * @param newHandle is the handle to the new database receiving the copy
	 * @throws IOException
	 * @throws CancelledException
	 */
	private void copyTable(Table oldTable,PackedDBHandle newHandle) throws IOException, CancelledException {
																// Pull out table configuration elements
		String tableName = oldTable.getName();					// Name
		Schema schema = oldTable.getSchema();					// Schema
		int[] indexedColumns = oldTable.getIndexedColumns();	// Secondardy indices
		
		Table newTable = newHandle.createTable(tableName, schema, indexedColumns);	// Create new table
		monitor.setMessage("Copying table: "+tableName);
		monitor.setMaximum(oldTable.getRecordCount());
		monitor.setProgress(0);
		RecordIterator iterator = oldTable.iterator();
		while(iterator.hasNext()) {								// Iterate through old records
			DBRecord record = iterator.next();
			newTable.putRecord(record);							// Copy as is into new table
			monitor.checkCanceled();
			monitor.incrementProgress(1);
		}
	}

	@Override
	protected void run() throws Exception {
		File file = askFile("Select FID database file to repack","OK");
		PackedDatabase pdb;
		pdb = PackedDatabase.getPackedDatabase(file, false, TaskMonitorAdapter.DUMMY_MONITOR);
		DBHandle handle = pdb.open(TaskMonitorAdapter.DUMMY_MONITOR);
		File saveFile = askFile("Select name for copy","OK");
		PackedDBHandle newHandle = new PackedDBHandle(pdb.getContentType());

		Table[] tables = handle.getTables();
		for(int i=0;i<tables.length;++i) {
			long transactionID = newHandle.startTransaction();
			copyTable(tables[i],newHandle);
			newHandle.endTransaction(transactionID, true);			
		}
		newHandle.saveAs(pdb.getContentType(), saveFile.getParentFile(),saveFile.getName(), TaskMonitorAdapter.DUMMY_MONITOR);
		newHandle.close();
	}
}
