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
import ghidra.program.database.util.DBRecordAdapter;
import ghidra.program.model.data.CompositeInternal;
import ghidra.util.UniversalID;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access the Composite database table.
 */
abstract class CompositeDBAdapter implements DBRecordAdapter {

	static final String COMPOSITE_TABLE_NAME = "Composite Data Types";
	static final Schema COMPOSITE_SCHEMA = CompositeDBAdapterV5V6.V5V6_COMPOSITE_SCHEMA;

	static final int COMPOSITE_NAME_COL = CompositeDBAdapterV5V6.V5V6_COMPOSITE_NAME_COL;
	static final int COMPOSITE_COMMENT_COL = CompositeDBAdapterV5V6.V5V6_COMPOSITE_COMMENT_COL;
	static final int COMPOSITE_IS_UNION_COL = CompositeDBAdapterV5V6.V5V6_COMPOSITE_IS_UNION_COL;
	static final int COMPOSITE_CAT_COL = CompositeDBAdapterV5V6.V5V6_COMPOSITE_CAT_COL;
	static final int COMPOSITE_LENGTH_COL = CompositeDBAdapterV5V6.V5V6_COMPOSITE_LENGTH_COL;
	static final int COMPOSITE_ALIGNMENT_COL = CompositeDBAdapterV5V6.V5V6_COMPOSITE_ALIGNMENT_COL;
	static final int COMPOSITE_NUM_COMPONENTS_COL =
		CompositeDBAdapterV5V6.V5V6_COMPOSITE_NUM_COMPONENTS_COL;
	static final int COMPOSITE_SOURCE_ARCHIVE_ID_COL =
		CompositeDBAdapterV5V6.V5V6_COMPOSITE_SOURCE_ARCHIVE_ID_COL;
	static final int COMPOSITE_UNIVERSAL_DT_ID =
		CompositeDBAdapterV5V6.V5V6_COMPOSITE_UNIVERSAL_DT_ID_COL;
	static final int COMPOSITE_SOURCE_SYNC_TIME_COL =
		CompositeDBAdapterV5V6.V5V6_COMPOSITE_SOURCE_SYNC_TIME_COL;
	static final int COMPOSITE_LAST_CHANGE_TIME_COL =
		CompositeDBAdapterV5V6.V5V6_COMPOSITE_LAST_CHANGE_TIME_COL;
	static final int COMPOSITE_PACKING_COL = CompositeDBAdapterV5V6.V5V6_COMPOSITE_PACK_COL;
	static final int COMPOSITE_MIN_ALIGN_COL = CompositeDBAdapterV5V6.V5V6_COMPOSITE_MIN_ALIGN_COL;

	// Stored Packing and Minimum Alignment values are consistent with CompositeInternal

	static final int FLEX_ARRAY_ELIMINATION_SCHEMA_VERSION = 6;

	private boolean flexArrayMigrationRequired = false; // signals flex-array migration required

	/**
	 * After construction for UPGRADE mode this method can be used to determine if
	 * a migration of all Struture flex-array components is required.
	 * @return true if flex-array migration required, else false
	 */
	final boolean isFlexArrayMigrationRequired() {
		return flexArrayMigrationRequired;
	}

	/**
	 * Gets an adapter for working with the composite data type database table.
	 * The composite table is used to store structures and unions. The adapter is based
	 * on the version of the database associated with the specified database handle and the openMode.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param tablePrefix prefix to be used with default table name
	 * @param monitor the monitor to use for displaying status or for canceling.
	 * @return the adapter for accessing the table of composite data types.
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there is trouble accessing the database.
	 * @throws CancelledException task cancelled
	 */
	static CompositeDBAdapter getAdapter(DBHandle handle, OpenMode openMode, String tablePrefix,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {
		try {
			return new CompositeDBAdapterV5V6(handle, openMode, tablePrefix);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == OpenMode.UPDATE) {
				throw e;
			}
			CompositeDBAdapter adapter = findReadOnlyAdapter(handle, tablePrefix);
			if (openMode == OpenMode.UPGRADE) {
				return upgrade(handle, adapter, tablePrefix, monitor);
			}
			return adapter;
		}
	}

	/**
	 * Tries to get a read only adapter for the database whose handle is passed to this method.
	 * @param handle handle to prior version of the database.
	 * @param tablePrefix prefix to be used with default table name
	 * @return the read only Composite data type table adapter
	 * @throws VersionException if a read only adapter can't be obtained for the database handle's version.
	 * @throws IOException if IO error occurs
	 */
	private static CompositeDBAdapter findReadOnlyAdapter(DBHandle handle, String tablePrefix)
			throws VersionException, IOException {
		try {
			return new CompositeDBAdapterV5V6(handle, OpenMode.IMMUTABLE, tablePrefix);
		}
		catch (VersionException e) {
			// ignore
		}
		try {
			return new CompositeDBAdapterV2V4(handle);
		}
		catch (VersionException e) {
			// ignore
		}
		try {
			return new CompositeDBAdapterV1(handle);
		}
		catch (VersionException e) {
			// ignore
		}
		return new CompositeDBAdapterV0(handle);
	}

	/**
	 * Upgrades the Composite data type table from the oldAdapter's version to the current version.
	 * @param handle handle to the database whose table is to be upgraded to a newer version.
	 * @param oldAdapter the adapter for the existing table to be upgraded.
	 * @param tablePrefix prefix to be used with default table name
	 * @param monitor task monitor
	 * @return the adapter for the new upgraded version of the table.
	 * @throws VersionException if the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if the database can't be read or written.
	 * @throws CancelledException user cancelled upgrade
	 */
	private static CompositeDBAdapter upgrade(DBHandle handle, CompositeDBAdapter oldAdapter,
			String tablePrefix, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		DBHandle tmpHandle = new DBHandle();
		long id = tmpHandle.startTransaction();
		CompositeDBAdapter tmpAdapter = null;
		try {
			tmpAdapter = new CompositeDBAdapterV5V6(tmpHandle, OpenMode.CREATE, tablePrefix);
			RecordIterator it = oldAdapter.getRecords();
			while (it.hasNext()) {
				monitor.checkCancelled();
				DBRecord rec = it.next();
				tmpAdapter.updateRecord(rec, false);
			}
			oldAdapter.deleteTable(handle);
			CompositeDBAdapter newAdapter =
				new CompositeDBAdapterV5V6(handle, OpenMode.CREATE, tablePrefix);
			if (oldAdapter.getVersion() < FLEX_ARRAY_ELIMINATION_SCHEMA_VERSION) {
				newAdapter.flexArrayMigrationRequired = true;
			}
			it = tmpAdapter.getRecords();
			while (it.hasNext()) {
				monitor.checkCancelled();
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
	 * Get the adapter schema version
	 * @return adapter schema version
	 */
	abstract int getVersion();

	/**
	 * Creates a database record for a composite data type (structure or union).
	 * @param name the unique name for this data type
	 * @param comments comments about this data type
	 * @param isUnion true indicates this data type is a union and all component offsets are at zero.
	 * @param categoryID the ID for the category that contains this array.
	 * @param length the total length or size of this data type.
	 * @param computedAlignment computed alignment for composite or -1 if not yet computed
	 * @param sourceArchiveID the ID for the source archive where this data type originated.
	 * @param sourceDataTypeID the ID of the associated data type in the source archive.
	 * @param lastChangeTime the time this data type was last changed.
	 * @param packValue {@link CompositeInternal#NO_PACKING}, {@link CompositeInternal#DEFAULT_PACKING}
	 * or the explicit pack value currently in use by this data type (positive value).
	 * @param minAlignment {@link CompositeInternal#DEFAULT_ALIGNMENT}, {@link CompositeInternal#MACHINE_ALIGNMENT}
	 * or the minimum alignment value currently in use by this data type (positive value).
	 * @return the database record for this data type.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract DBRecord createRecord(String name, String comments, boolean isUnion, long categoryID,
			int length, int computedAlignment, long sourceArchiveID, long sourceDataTypeID,
			long lastChangeTime, int packValue, int minAlignment) throws IOException;

	/**
	 * Gets a composite data type record from the database based on its ID.
	 * @param dataTypeID the data type's ID.
	 * @return the record for the composite (structure or union) data type.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract DBRecord getRecord(long dataTypeID) throws IOException;

	/**
	 * Gets an iterator over all composite (structure and union) data type records.
	 * @return the composite data type record iterator.
	 * @throws IOException if the database can't be accessed.
	 */
	@Override
	public abstract RecordIterator getRecords() throws IOException;

	/**
	 * Updates the composite data type table with the provided record.
	 * @param record the new record
	 * @param setLastChangeTime true means change the last change time in the record to the
	 * current time before putting the record in the database.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract void updateRecord(DBRecord record, boolean setLastChangeTime) throws IOException;

	/**
	 * Removes the composite data type record with the specified ID.
	 * @param dataID the ID of the data type.
	 * @return true if the record is removed.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract boolean removeRecord(long dataID) throws IOException;

	/**
	 * Deletes the composite data type table from the database with the specified database handle.
	 * @param handle handle to the database where the table should get deleted.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract void deleteTable(DBHandle handle) throws IOException;

	/**
	 * Gets all the composite data types that are contained in the category that has the indicated ID.
	 * @param categoryID the category whose composite data types are wanted.
	 * @return an array of IDs as LongField values within Field array for the
	 * composite data types in the category.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract Field[] getRecordIdsInCategory(long categoryID) throws IOException;

	/**
	 * Gets an array with the IDs of all data types in the composite table that were derived
	 * from the source data type archive indicated by the source archive ID.
	 * @param archiveID the ID of the source archive whose data types we want.
	 * @return the array data type IDs.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract Field[] getRecordIdsForSourceArchive(long archiveID) throws IOException;

	/**
	 * Get composite record whose sourceID and datatypeID match the specified Universal IDs.
	 * @param sourceID universal source archive ID
	 * @param datatypeID universal datatype ID
	 * @return composite record found or null
	 * @throws IOException if IO error occurs
	 */
	abstract DBRecord getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID)
			throws IOException;

	/**
	 * Get the number of composite datatype records
	 * @return total number of composite records
	 */
	@Override
	public abstract int getRecordCount();

}
