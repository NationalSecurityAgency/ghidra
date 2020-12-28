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
package db;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * MasterTable manages data pertaining to all other tables within the database - 
 * this includes index tables.
 * The first buffer associated with this table is managed by the DBParms 
 * object associated with the database.
 */
class MasterTable {

	private TableRecord masterRecord;

	private DBHandle dbh;
	private DBParms dbParms;
	private Table table;

	// List of table records sorted by tablenum
	TableRecord[] tableRecords;

	private long nextTableNum = 0;

	/**
	 * Construct an existing master table.
	 * @param dbh database handle
	 * @throws IOException database IO error
	 */
	MasterTable(DBHandle dbh) throws IOException {
		this.dbh = dbh;
		this.dbParms = dbh.getDBParms();

		masterRecord = new TableRecord(0, "MASTER", TableRecord.getTableRecordSchema(), -1);
		try {
			masterRecord.setRootBufferId(dbParms.get(DBParms.MASTER_TABLE_ROOT_BUFFER_ID_PARM));
		}
		catch (ArrayIndexOutOfBoundsException e) {
			throw new IOException("Corrupt database parameters", e);
		}

		table = new Table(dbh, masterRecord);
		ArrayList<TableRecord> trList = new ArrayList<TableRecord>();
		RecordIterator it = table.iterator();
		while (it.hasNext()) {
			trList.add(new TableRecord(dbh, it.next()));
		}
		tableRecords = new TableRecord[trList.size()];
		trList.toArray(tableRecords);
		if (tableRecords.length > 0) {
			nextTableNum = tableRecords[tableRecords.length - 1].getTableNum() + 1;
		}
	}

	/**
	 * Create a new table record and add to master table.
	 * If this is an index table the name corresponds to the table which is
	 * indexed.  This method should be invoked for index tables immediately
	 * following the creation of the indexed table.
	 * This method may only be invoked while a database transaction 
	 * is in progress. 
	 * @param name name of table.
	 * @param tableSchema table schema
	 * @param indexedColumn primary table index key column, or -1 for primary table
	 * @return new table record
	 * @throws IOException database IO error
	 */
	TableRecord createTableRecord(String name, Schema tableSchema, int indexedColumn)
			throws IOException {

		// Create new table record
		TableRecord tableRecord = new TableRecord(nextTableNum++, name, tableSchema, indexedColumn);
		table.putRecord(tableRecord.getRecord());

		// Update master root which may have changed
		dbParms.set(DBParms.MASTER_TABLE_ROOT_BUFFER_ID_PARM, masterRecord.getRootBufferId());

		// Update tableRecord list
		TableRecord[] newList = new TableRecord[tableRecords.length + 1];
		System.arraycopy(tableRecords, 0, newList, 0, tableRecords.length);
		newList[tableRecords.length] = tableRecord;
		Arrays.sort(newList);
		tableRecords = newList;

		return tableRecord;
	}

	/**
	 * Remove the master table record associated with the specified table name.
	 * This method may only be invoked while a database transaction 
	 * is in progress. 
	 * @param tableNum table number (key within master table)
	 * @throws IOException database IO error
	 */
	void deleteTableRecord(long tableNum) throws IOException {

		// Locate tableRecord to be deleted
		for (int i = 0; i < tableRecords.length; i++) {
			if (tableRecords[i].getTableNum() == tableNum) {
				if (tableRecords[i].getRootBufferId() >= 0)
					throw new IOException("Can not delete non-empty table");
				table.deleteRecord(tableNum);
				tableRecords[i].invalidate();

				// Update master root which may have changed
				dbParms.set(DBParms.MASTER_TABLE_ROOT_BUFFER_ID_PARM,
					masterRecord.getRootBufferId());

				// Update tableRecord list
				TableRecord[] newList = new TableRecord[tableRecords.length - 1];
				System.arraycopy(tableRecords, 0, newList, 0, i);
				System.arraycopy(tableRecords, i + 1, newList, i, tableRecords.length - i - 1);
				tableRecords = newList;
				return;
			}
		}
		throw new IOException("Table not found");
	}

	/**
	 * Get a list of all tables defined within this master table.
	 * Records are returned in the list ordered by their table number key.
	 * @return array of table records defining each table.
	 */
	TableRecord[] getTableRecords() {
		return tableRecords;
	}

	/**
	 * Refresh table data from the master table.
	 * Records are returned in the list ordered by their table number key.
	 * @return the update list of master table records.
	 * @throws IOException database IO error
	 */
	TableRecord[] refreshTableRecords() throws IOException {

		try {
			int masterRootId = dbParms.get(DBParms.MASTER_TABLE_ROOT_BUFFER_ID_PARM);
			if (masterRecord.getRootBufferId() != masterRootId) {
				masterRecord.setRootBufferId(masterRootId);
				table.tableRecordChanged();
			}
		}
		catch (ArrayIndexOutOfBoundsException e) {
			throw new IOException("Corrupt database parameters", e);
		}

		ArrayList<TableRecord> trList = new ArrayList<TableRecord>();

		int ix = 0;
		int oldTableCnt = tableRecords.length;
		RecordIterator it = table.iterator();
		while (it.hasNext()) {
			DBRecord rec = it.next();
			long tablenum = rec.getKey();

			while (ix < tableRecords.length && tablenum > tableRecords[ix].getTableNum()) {
				tableRecords[ix++].invalidate();  // table no longer exists
			}

			if (ix == oldTableCnt || tablenum < tableRecords[ix].getTableNum()) {
				trList.add(new TableRecord(dbh, rec));  // new table
			}
			else if (tablenum == tableRecords[ix].getTableNum()) {
				tableRecords[ix].setRecord(dbh, rec);
				trList.add(tableRecords[ix++]);    // update existing table
			}
		}

		while (ix < tableRecords.length) {
			tableRecords[ix++].invalidate();  // table no longer exists
		}

		tableRecords = trList.toArray(new TableRecord[trList.size()]);
		return tableRecords;
	}

	/**
	 * Flush all unsaved table changes to the underlying buffer mgr.
	 * This method may only be invoked while a database transaction 
	 * is in progress. 
	 * @throws IOException database IO error
	 */
	void flush() throws IOException {
		for (int i = 0; i < tableRecords.length; i++) {
			DBRecord rec = tableRecords[i].getRecord();
			if (rec.isDirty()) {
				table.putRecord(rec);
			}
		}
	}

	/**
	 * Change the name of a table and its associated indexes.
	 * @param oldName old table name
	 * @param newName new tablename
	 */
	void changeTableName(String oldName, String newName) {
		for (int i = 0; i < tableRecords.length; i++) {
			if (oldName.equals(tableRecords[i].getName())) {
				tableRecords[i].setName(newName);
			}
		}
	}

}
