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
import java.util.Iterator;
import java.util.List;

import db.*;
import ghidra.program.model.data.SourceArchive;
import ghidra.util.UniversalID;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access the data type archive identifier table.
 * This table holds an ID entry for each archive that has provided a data type to the 
 * data type manager for the program.
 */
abstract class SourceArchiveAdapter {

	static final String TABLE_NAME = "Data Type Archive IDs";
	static final Schema SCHEMA = SourceArchiveAdapterV0.V0_SCHEMA;
	// Data Type Archive ID Columns
	static final int ARCHIVE_ID_DOMAIN_FILE_ID_COL =
		SourceArchiveAdapterV0.V0_ARCHIVE_ID_DOMAIN_FILE_ID_COL;
	static final int ARCHIVE_ID_NAME_COL = SourceArchiveAdapterV0.V0_ARCHIVE_ID_NAME_COL;
	static final int ARCHIVE_ID_TYPE_COL = SourceArchiveAdapterV0.V0_ARCHIVE_ID_TYPE_COL;
	static final int ARCHIVE_ID_LAST_SYNC_TIME_COL =
		SourceArchiveAdapterV0.V0_ARCHIVE_ID_LAST_SYNC_TIME_COL;
	static final int ARCHIVE_ID_DIRTY_FLAG_COL =
		SourceArchiveAdapterV0.V0_ARCHIVE_ID_DIRTY_FLAG_COL;

	/**
	 * Gets an adapter for working with the Data Type Archive ID database table. This table is 
	 * intended to associate a unique ID with a particular project data type archive. When a data 
	 * type is added to a program it can indicate save the ID of the archive where it originated. 
	 * This can then be used to synchronize the program with that archive. The adapter is based 
	 * on the version of the database associated with the specified database handle and the openMode.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param monitor the monitor to use for displaying status or for canceling.
	 * @return the adapter for accessing the table of data type archive ID entries.
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there is trouble accessing the database.
	 */
	static SourceArchiveAdapter getAdapter(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, IOException {
		if (openMode == DBConstants.CREATE) {
			return new SourceArchiveAdapterV0(handle, true);
		}
		try {
			return new SourceArchiveAdapterV0(handle, false);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			SourceArchiveAdapter adapter = findReadOnlyAdapter(handle);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter);
			}
			return adapter;
		}
	}

	/**
	 * Tries to get a read only adapter for the database whose handle is passed to this method.
	 * @param handle handle to prior version of the database.
	 * @return the read only Data Type Archive ID table adapter
	 * @throws VersionException if a read only adapter can't be obtained for the database handle's version.
	 */
	static SourceArchiveAdapter findReadOnlyAdapter(DBHandle handle) {
		return new SourceArchiveAdapterNoTable(handle);
	}

	/**
	 * Upgrades the DataType Archive ID table from the oldAdapter's version to the current version.
	 * @param handle handle to the database whose table is to be upgraded to a newer version.
	 * @param oldAdapter the adapter for the existing table to be upgraded.
	 * @return the adapter for the new upgraded version of the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if the database can't be read or written.
	 */
	static SourceArchiveAdapter upgrade(DBHandle handle, SourceArchiveAdapter oldAdapter)
			throws VersionException, IOException {

		DBHandle tmpHandle = new DBHandle();
		long id = tmpHandle.startTransaction();
		SourceArchiveAdapter tmpAdapter = null;
		try {
			tmpAdapter = new SourceArchiveAdapterV0(tmpHandle, true);
			Iterator<DBRecord> it = oldAdapter.getRecords().iterator();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				tmpAdapter.updateRecord(rec);
			}
			oldAdapter.deleteTable(handle);
			SourceArchiveAdapter newAdapter = new SourceArchiveAdapterV0(handle, true);
			it = tmpAdapter.getRecords().iterator();
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

	abstract void deleteTable(DBHandle handle) throws IOException;

	/**
	 * Creates a new source archive record using the information from the given source archive.
	 * @param sourceArchive the source archive from which to get the archive information.
	 */
	abstract DBRecord createRecord(SourceArchive sourceArchive) throws IOException;

	/**
	 * Returns a list containing all records in the archive table
	 * @return
	 */
	abstract List<DBRecord> getRecords() throws IOException;

	/**
	 * Returns the record for the given key (sourceArchiveID)
	 */
	abstract DBRecord getRecord(long key) throws IOException;

	/**
	 * Updates the data type archive ID table with the provided record.
	 * @param record the new record
	 * @throws IOException if the database can't be accessed.
	 */
	abstract void updateRecord(DBRecord record) throws IOException;

	/**
	 * Remove the record for the given data type archive ID.
	 * @param dataTypeArchiveID ID of data type archive record to delete
	 * @return true if the record was deleted
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract boolean removeRecord(long key) throws IOException;

	/**
	 * Removes the record for the given sourceArchive ID.
	 * @param sourceArchiveID the id for which to remove its record.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract void deleteRecord(UniversalID sourceArchiveID) throws IOException;

}
