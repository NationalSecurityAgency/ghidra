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
// Repack FID database file to eliminate unused blocks and possibly make indices more efficient.
// This script can be executed in both GUI and headless modes.
//@category FunctionID
import java.io.File;
import java.io.IOException;

import db.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.store.db.PackedDBHandle;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

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
			monitor.checkCancelled();
			monitor.incrementProgress(1);
		}
	}

	@Override
	protected void run() throws Exception {
		File file;
		File saveFile;
		// headless mode: `askFile()` cannot be used to specify the output file in headless mode
		// because the file does not exist yet and `IllegalArgumentException` will be raised
		if (getScriptArgs().length == 2) {
			file = new File(getScriptArgs()[0]);
			saveFile = new File(getScriptArgs()[1]);
		}
		// GUI mode
		else {
			file = askFile("Select FID database file to repack","OK");
			saveFile = askFile("Select name for copy","OK");
		}
		PackedDatabase pdb;
		pdb = PackedDatabase.getPackedDatabase(file, false, TaskMonitor.DUMMY);
		DBHandle handle = pdb.open(TaskMonitor.DUMMY);
		PackedDBHandle newHandle = new PackedDBHandle(pdb.getContentType());

		Table[] tables = handle.getTables();
		for(int i=0;i<tables.length;++i) {
			long transactionID = newHandle.startTransaction();
			copyTable(tables[i],newHandle);
			newHandle.endTransaction(transactionID, true);			
		}
		newHandle.saveAs(pdb.getContentType(), saveFile.getParentFile(),saveFile.getName(), TaskMonitor.DUMMY);
		newHandle.close();
	}
}
