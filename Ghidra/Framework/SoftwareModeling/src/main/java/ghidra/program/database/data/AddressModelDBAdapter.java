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
import ghidra.framework.data.OpenMode;
import ghidra.util.UniversalID;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access the Address Model database table.
 */
abstract class AddressModelDBAdapter {

	static final String ADDRESS_MODEL_TABLE_NAME = "Address Models";
	static final Schema ADDRESS_MODEL_SCHEMA = AddressModelDBAdapterV0.V0_ADDRESS_MODEL_SCHEMA;

	static final int ADDRESS_MODEL_DT_ID_COL = AddressModelDBAdapterV0.V0_ADDRESS_MODEL_DT_ID_COL;
	static final int ADDRESS_MODEL_ID_COL = AddressModelDBAdapterV0.V0_ADDRESS_MODEL_ID_COL;

	/**
	 * Gets an adapter for working with the Address Model data type database table. The adapter is based
	 * on the version of the database associated with the specified database handle and the openMode.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param monitor the monitor to use for displaying status or for cancelling.
	 * @return the adapter for accessing the table of Address Model data types.
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there is trouble accessing the database.
	 */
	static AddressModelDBAdapter getAdapter(DBHandle handle, OpenMode openMode,
			TaskMonitor monitor) throws VersionException, IOException {
		try {
			return new AddressModelDBAdapterV0(handle, openMode);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == OpenMode.UPDATE) {
				throw e;
			}
			AddressModelDBAdapter adapter = findReadOnlyAdapter(handle);
			if (openMode == OpenMode.UPGRADE) {
				adapter = upgrade(handle, adapter);
			}
			return adapter;
		}
	}

	/**
	 * Tries to get a read only adapter for the database whose handle is passed to this method.
	 * @param handle handle to prior version of the database.
	 * @return the read only Address Model data type table adapter
	 * @throws VersionException if a read only adapter can't be obtained for the database handle's version.
	 * @throws IOException if unable to access database.
	 */
	static AddressModelDBAdapter findReadOnlyAdapter(DBHandle handle)
			throws VersionException, IOException {
		try {
			return new AddressModelDBAdapterV0(handle, OpenMode.IMMUTABLE);
		}
		catch (VersionException e) {
			if (!e.isUpgradable()) {
				throw e;
			}
		}

		return new AddressModelDBAdapterNoTable(handle);
	}

	/**
	 * Upgrades the Address Model data type table from the oldAdapter's version to the current version.
	 * @param handle handle to the database whose table is to be upgraded to a newer version.
	 * @param oldAdapter the adapter for the existing table to be upgraded.
	 * @return the adapter for the new upgraded version of the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if the database can't be read or written.
	 */
	static AddressModelDBAdapter upgrade(DBHandle handle,
			AddressModelDBAdapter oldAdapter) throws VersionException, IOException {

		DBHandle tmpHandle = new DBHandle();
		long id = tmpHandle.startTransaction();
		AddressModelDBAdapter tmpAdapter = null;
		try {
			tmpAdapter = new AddressModelDBAdapterV0(tmpHandle, OpenMode.CREATE);
			RecordIterator it = oldAdapter.getRecords();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				tmpAdapter.updateRecord(rec, false);
			}
			oldAdapter.deleteTable(handle);
			AddressModelDBAdapterV0 newAdapter =
				new AddressModelDBAdapterV0(handle, OpenMode.CREATE);
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
	 * Creates a database record for the data types associated Address Model.
	 * @param dataTypeID data type ID associated with the Address Model.
	 * @param modelID the ID of the Address Model.
	 * @return the database record for this data type.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract DBRecord createRecord(long dataTypeID, byte modelID) throws IOException;

	/**
	 * Gets a Address Model data type record from the database based on its ID.
	 * @param dataTypeID the data type's ID.
	 * @return the record for the Address Model data type.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract DBRecord getRecord(long dataTypeID) throws IOException;

	/**
	 * Gets an iterator over all Address Model data type records.
	 * @return the Address Model data type record iterator.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract RecordIterator getRecords() throws IOException;

	/**
	 * Removes the Address Model data type record with the specified ID.
	 * @param dataTypeID the ID of the data type.
	 * @return true if the record is removed.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract boolean removeRecord(long dataTypeID) throws IOException;

	/**
	 * Updates the Address Model data type table with the provided record.
	 * @param record the new record
	 * @param setLastChangeTime true means change the last change time in the record to the
	 * current time before putting the record in the database.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract void updateRecord(DBRecord record, boolean setLastChangeTime) throws IOException;

	/**
	 * Deletes the Address Model data type table from the database with the specified database handle.
	 * @param handle handle to the database where the table should get deleted.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract void deleteTable(DBHandle handle) throws IOException;

	/**
	 * Gets an array with the IDs of all data types in the Address Model table that were derived
	 * from the source data type archive indicated by the source archive ID.
	 * @param archiveID the ID of the source archive whose data types we want.
	 * @return the array data type IDs.
	 * @throws IOException if the database can't be accessed.
	 */
//	abstract Field[] getRecordIdsForSourceArchive(long archiveID) throws IOException;

	/**
	 * Get Address Model record whose sourceID and datatypeID match the specified Universal IDs.
	 * @param sourceID universal source archive ID
	 * @param datatypeID universal datatype ID
	 * @return Address Model record found or null
	 * @throws IOException if IO error occurs
	 */
//	abstract DBRecord getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID)
//			throws IOException;

}
