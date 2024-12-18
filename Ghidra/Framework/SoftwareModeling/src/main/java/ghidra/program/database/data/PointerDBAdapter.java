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
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access the Pointer database table for Pointer data types.
 *
 */
abstract class PointerDBAdapter implements RecordTranslator {
	static final String POINTER_TABLE_NAME = "Pointers";

	static final Schema SCHEMA = new Schema(PointerDBAdapterV2.VERSION, "Pointer ID",
		new Field[] { LongField.INSTANCE, LongField.INSTANCE, ByteField.INSTANCE },
		new String[] { "Data Type ID", "Category ID", "Length" });

	static final int PTR_DT_ID_COL = 0;
	static final int PTR_CATEGORY_COL = 1;
	static final int PTR_LENGTH_COL = 2;

	/**
	 * Gets an adapter for working with the enumeration data type values database table. The adapter is based
	 * on the version of the database associated with the specified database handle and the openMode.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param tablePrefix prefix to be used with default table name
	 * @param monitor the monitor to use for displaying status or for canceling.
	 * @return the adapter for accessing the table of enumeration data type values.
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there is trouble accessing the database.
	 * @throws CancelledException if task is cancelled
	 */
	static PointerDBAdapter getAdapter(DBHandle handle, OpenMode openMode, String tablePrefix,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {

		if (openMode == OpenMode.CREATE) {
			return new PointerDBAdapterV2(handle, tablePrefix, true);
		}
		try {
			return new PointerDBAdapterV2(handle, tablePrefix, false);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == OpenMode.UPDATE) {
				throw e;
			}
			PointerDBAdapter adapter = findReadOnlyAdapter(handle);
			if (openMode == OpenMode.UPGRADE) {
				adapter = upgrade(handle, adapter, tablePrefix, monitor);
			}
			return adapter;
		}
	}

	static PointerDBAdapter findReadOnlyAdapter(DBHandle handle) throws VersionException {
		try {
			return new PointerDBAdapterV1(handle);
		}
		catch (VersionException e) {
			return new PointerDBAdapterV0(handle);
		}
	}

	static PointerDBAdapter upgrade(DBHandle handle, PointerDBAdapter oldAdapter,
			String tablePrefix, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		DBHandle tmpHandle = new DBHandle();
		long id = tmpHandle.startTransaction();
		PointerDBAdapter tmpAdapter = null;
		try {
			tmpAdapter = new PointerDBAdapterV2(tmpHandle, tablePrefix, true);
			RecordIterator it = oldAdapter.getRecords();
			while (it.hasNext()) {
				monitor.checkCancelled();
				DBRecord rec = it.next();
				tmpAdapter.updateRecord(rec);
			}
			oldAdapter.deleteTable(handle);
			PointerDBAdapter newAdapter = new PointerDBAdapterV2(handle, tablePrefix, true);
			it = tmpAdapter.getRecords();
			while (it.hasNext()) {
				monitor.checkCancelled();
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
	 * Create a pointer record.
	 * @param dataTypeID data type ID of the date type being pointed to
	 * @param categoryID the category ID of the datatype
	 * @param length pointer size in bytes
	 * @return the record
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord createRecord(long dataTypeID, long categoryID, int length) throws IOException;

	/**
	 * Get the record with the given pointerID.
	 * @param pointerID database key
	 * @return requested pointer record or null if not found
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getRecord(long pointerID) throws IOException;

	/**
	 * An iterator over the records of this adapter
	 * @return the iterator
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getRecords() throws IOException;

	/**
	 * Delete the record.
	 * @param pointerID database key
	 * @return true if the record was deleted
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract boolean removeRecord(long pointerID) throws IOException;

	/**
	 * Update the record in the table.
	 * @param record pointer record to be updated
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void updateRecord(DBRecord record) throws IOException;

	/**
	 * Gets all the pointer data types that are contained in the category that
	 * have the indicated ID.
	 * @param categoryID the category whose pointer data types are wanted.
	 * @return an array of IDs for the pointer data types in the category.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract Field[] getRecordIdsInCategory(long categoryID) throws IOException;

	/**
	 * Get the number of pointer datatype records
	 * @return total number of composite records
	 */
	public abstract int getRecordCount();
}
