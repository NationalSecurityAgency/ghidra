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
import ghidra.util.UniversalID;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access the database table for typedef data types.
 */
abstract class TypedefDBAdapter {

	static final String TYPEDEF_TABLE_NAME = "Typedefs";
	static final Schema SCHEMA = TypedefDBAdapterV1.V1_SCHEMA;

	static final int TYPEDEF_DT_ID_COL = TypedefDBAdapterV1.V1_TYPEDEF_DT_ID_COL;
	static final int TYPEDEF_NAME_COL = TypedefDBAdapterV1.V1_TYPEDEF_NAME_COL;
	static final int TYPEDEF_CAT_COL = TypedefDBAdapterV1.V1_TYPEDEF_CAT_COL;
	static final int TYPEDEF_SOURCE_ARCHIVE_ID_COL =
		TypedefDBAdapterV1.V1_TYPEDEF_SOURCE_ARCHIVE_ID_COL;
	static final int TYPEDEF_UNIVERSAL_DT_ID_COL =
		TypedefDBAdapterV1.V1_TYPEDEF_UNIVERSAL_DT_ID_COL;
	static final int TYPEDEF_SOURCE_SYNC_TIME_COL =
		TypedefDBAdapterV1.V1_TYPEDEF_SOURCE_SYNC_TIME_COL;
	static final int TYPEDEF_LAST_CHANGE_TIME_COL =
		TypedefDBAdapterV1.V1_TYPEDEF_LAST_CHANGE_TIME_COL;

	/**
	 * Gets an adapter for working with the Typedef data type database table. The adapter is based 
	 * on the version of the database associated with the specified database handle and the openMode.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param monitor the monitor to use for displaying status or for canceling.
	 * @return the adapter for accessing the table of Typedef data types.
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there is trouble accessing the database.
	 */
	static TypedefDBAdapter getAdapter(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, IOException {
		try {
			return new TypedefDBAdapterV1(handle, openMode == DBConstants.CREATE);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			TypedefDBAdapter adapter = findReadOnlyAdapter(handle);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter);
			}
			return adapter;
		}
	}

	/**
	 * Tries to get a read only adapter for the database whose handle is passed to this method.
	 * @param handle handle to prior version of the database.
	 * @return the read only Typedef table adapter
	 * @throws VersionException if a read only adapter can't be obtained for the database handle's version.
	 */
	static TypedefDBAdapter findReadOnlyAdapter(DBHandle handle) throws VersionException {
		return new TypedefDBAdapterV0(handle);
	}

	/**
	 * Upgrades the Typedef data type table from the oldAdapter's version to the current version.
	 * @param handle handle to the database whose table is to be upgraded to a newer version.
	 * @param oldAdapter the adapter for the existing table to be upgraded.
	 * @return the adapter for the new upgraded version of the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if the database can't be read or written.
	 */
	static TypedefDBAdapter upgrade(DBHandle handle, TypedefDBAdapter oldAdapter)
			throws VersionException, IOException {

		DBHandle tmpHandle = new DBHandle();
		long id = tmpHandle.startTransaction();
		TypedefDBAdapter tmpAdapter = null;
		try {
			tmpAdapter = new TypedefDBAdapterV1(tmpHandle, true);
			RecordIterator it = oldAdapter.getRecords();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				tmpAdapter.updateRecord(rec, false);
			}
			oldAdapter.deleteTable(handle);
			TypedefDBAdapter newAdapter = new TypedefDBAdapterV1(handle, true);
			it = tmpAdapter.getRecords();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				newAdapter.updateRecord(rec, false);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.endTransaction(id, true);
			tmpHandle.close();
		}
	}

	/**
	 * Creates a database record for a type definition data type.
	 * @param dataTypeID the ID of the data type that is referred to by this type definition.
	 * @param name the unique name for this data type
	 * @param categoryID the ID for the category that contains this data type.
	 * @param sourceArchiveID the ID for the source archive where this data type originated.
	 * @param sourceDataTypeID the ID of the associated data type in the source archive.
	 * @param lastChangeTime the time this data type was last changed.
	 * @return the database record for this data type.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract DBRecord createRecord(long dataTypeID, String name, long categoryID,
			long sourceArchiveID, long sourceDataTypeID, long lastChangeTime) throws IOException;

	/**
	 * Gets a type definition data type record from the database based on its ID.
	 * @param typedefID the data type's ID.
	 * @return the record for the type definition data type.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract DBRecord getRecord(long typedefID) throws IOException;

	/**
	 * Gets an iterator over all type definition data type records.
	 * @return the type definition data type record iterator.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract RecordIterator getRecords() throws IOException;

	/**
	 * Removes the type definition data type record with the specified ID.
	 * @param dataID the ID of the data type.
	 * @return true if the record is removed.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract boolean removeRecord(long dataID) throws IOException;

	/**
	 * Updates the type definition data type table with the provided record.
	 * @param record the new record
	 * @param setLastChangedTime true means change the last change time in the record to the 
	 * current time before putting the record in the database.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract void updateRecord(DBRecord record, boolean setLastChangeTime) throws IOException;

	/**
	 * Deletes the type definition data type table from the database with the specified database handle.
	 * @param handle handle to the database where the table should get deleted.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract void deleteTable(DBHandle handle) throws IOException;

	/**
	 * Gets all the type definition data types that are contained in the category that has the indicated ID.
	 * @param categoryID the category whose type definition data types are wanted.
	 * @return an array of IDs for the type definition data types in the category.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract Field[] getRecordIdsInCategory(long categoryID) throws IOException;

	/**
	 * Gets an array with the IDs of all data types in the type definition table that were derived
	 * from the source data type archive indicated by the source archive ID.
	 * @param archiveID the ID of the source archive whose data types we want.
	 * @return the array data type IDs.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract Field[] getRecordIdsForSourceArchive(long archiveID) throws IOException;

	/**
	 * Get typedef record whoose sourceID and datatypeID match the specified Universal IDs.
	 * @param sourceID universal source archive ID
	 * @param datatypeID universal datatype ID
	 * @return typedef record found or null
	 * @throws IOException if IO error occurs
	 */
	abstract DBRecord getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID)
			throws IOException;

}
