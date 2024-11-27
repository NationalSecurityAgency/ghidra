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
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.util.UniversalID;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access the Function Signature Definition database table.
 */
abstract class FunctionDefinitionDBAdapter implements DBRecordAdapter {

	static final String FUNCTION_DEF_TABLE_NAME = "Function Definitions";
	static final Schema FUN_DEF_SCHEMA = FunctionDefinitionDBAdapterV2.V2_FUN_DEF_SCHEMA;

	static final int FUNCTION_DEF_NAME_COL = FunctionDefinitionDBAdapterV2.V2_FUNCTION_DEF_NAME_COL;
	static final int FUNCTION_DEF_COMMENT_COL =
		FunctionDefinitionDBAdapterV2.V2_FUNCTION_DEF_COMMENT_COL;
	static final int FUNCTION_DEF_CAT_ID_COL =
		FunctionDefinitionDBAdapterV2.V2_FUNCTION_DEF_CAT_ID_COL;
	static final int FUNCTION_DEF_RETURN_ID_COL =
		FunctionDefinitionDBAdapterV2.V2_FUNCTION_DEF_RETURN_ID_COL;
	static final int FUNCTION_DEF_FLAGS_COL =
		FunctionDefinitionDBAdapterV2.V2_FUNCTION_DEF_FLAGS_COL;
	static final int FUNCTION_DEF_CALLCONV_COL =
		FunctionDefinitionDBAdapterV2.V2_FUNCTION_DEF_CALLCONV_COL;
	static final int FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL =
		FunctionDefinitionDBAdapterV2.V2_FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL;
	static final int FUNCTION_DEF_SOURCE_DT_ID_COL =
		FunctionDefinitionDBAdapterV2.V2_FUNCTION_DEF_UNIVERSAL_DT_ID_COL;
	static final int FUNCTION_DEF_SOURCE_SYNC_TIME_COL =
		FunctionDefinitionDBAdapterV2.V2_FUNCTION_DEF_SOURCE_SYNC_TIME_COL;
	static final int FUNCTION_DEF_LAST_CHANGE_TIME_COL =
		FunctionDefinitionDBAdapterV2.V2_FUNCTION_DEF_LAST_CHANGE_TIME_COL;

	static final byte FUNCTION_DEF_VARARG_FLAG = (byte) 0x1; // Bit 0 is flag for "has vararg".
	static final byte FUNCTION_DEF_NORETURN_FLAG = (byte) 0x2; // Bit 1 is flag for "has noreturn" (added with V2).

	/**
	 * Gets an adapter for working with the function definition data type database table. The adapter is based
	 * on the version of the database associated with the specified database handle and the openMode.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param tablePrefix prefix to be used with default table name
	 * @param callConvAdapter calling convention table adapter suitable to add new conventions
	 * (e.g., this adapter being used during upgrade operation).  Only used when openMode is 
	 * {@link OpenMode#UPGRADE} when adding new calling conventions must be permitted.
	 * @param monitor the monitor to use for displaying status or for canceling.
	 * @return the adapter for accessing the table of function definition data types.
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there is trouble accessing the database.
	 * @throws CancelledException if task is cancelled
	 */
	static FunctionDefinitionDBAdapter getAdapter(DBHandle handle, OpenMode openMode,
			String tablePrefix, CallingConventionDBAdapter callConvAdapter, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		if (openMode == OpenMode.CREATE) {
			return new FunctionDefinitionDBAdapterV2(handle, tablePrefix, true);
		}
		try {
			return new FunctionDefinitionDBAdapterV2(handle, tablePrefix, false);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == OpenMode.UPDATE) {
				throw e;
			}
			FunctionDefinitionDBAdapter adapter;
			if (openMode == OpenMode.UPGRADE) {
				adapter = findReadOnlyAdapter(handle, tablePrefix, callConvAdapter);
				adapter = upgrade(handle, adapter, tablePrefix, monitor);
			}
			else {
				adapter = findReadOnlyAdapter(handle, tablePrefix, null);
			}
			return adapter;
		}
	}

	/**
	 * Tries to get a read only adapter for the database whose handle is passed to this method.
	 * @param handle handle to prior version of the database.
	 * @param tablePrefix prefix to be used with default table name
	 * @param callConvAdapter calling convention table adapter suitable to add new conventions
	 * (e.g., this adapter being used during upgrade operation).  Should be null if not performing
	 * an upgrade.
	 * @return the read only Function Definition data type table adapter
	 * @throws VersionException if a read only adapter can't be obtained for the database handle's version.
	 */
	private static FunctionDefinitionDBAdapter findReadOnlyAdapter(DBHandle handle,
			String tablePrefix, CallingConventionDBAdapter callConvAdapter)
			throws VersionException {
		try {
			return new FunctionDefinitionDBAdapterV1(handle, tablePrefix, callConvAdapter);
		}
		catch (VersionException e) {
			// ignore
		}
		try {
			return new FunctionDefinitionDBAdapterV0(handle);
		}
		catch (VersionException e) {
			// ignore
		}

		return new FunctionDefinitionDBAdapterNoTable(handle);
	}

	/**
	 * Upgrades the Function Definition data type table from the oldAdapter's version to the current version.
	 * @param handle handle to the database whose table is to be upgraded to a newer version.
	 * @param oldAdapter the adapter for the existing table to be upgraded.
	 * @param tablePrefix prefix to be used with default table name
	 * @param monitor task monitor
	 * @return the adapter for the new upgraded version of the table.
	 * @throws VersionException if the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if the database can't be read or written.
	 * @throws CancelledException if task is cancelled
	 */
	private static FunctionDefinitionDBAdapter upgrade(DBHandle handle,
			FunctionDefinitionDBAdapter oldAdapter, String tablePrefix, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		DBHandle tmpHandle = new DBHandle();
		long id = tmpHandle.startTransaction();
		FunctionDefinitionDBAdapter tmpAdapter = null;
		try {
			tmpAdapter = new FunctionDefinitionDBAdapterV2(tmpHandle, tablePrefix, true);
			RecordIterator it = oldAdapter.getRecords();
			while (it.hasNext()) {
				monitor.checkCancelled();
				DBRecord rec = it.next();
				tmpAdapter.updateRecord(rec, false);
			}
			oldAdapter.deleteTable(handle);
			FunctionDefinitionDBAdapter newAdapter =
				new FunctionDefinitionDBAdapterV2(handle, tablePrefix, true);
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
	 * Creates a database record for an function signature definition data type.
	 * @param name the unique name for this data type.
	 * @param comments comments about this data type.
	 * @param categoryID the ID for the category that contains this data type.
	 * @param returnDtID the ID of the data type that is returned by this function definition.
	 * @param hasVarArgs true if this function definition has a variable length argument list.
	 * @param hasNoReturn true if this function definition has noreturn enabled
	 * @param callingConventionID calling convention ID
	 * @param sourceArchiveID the ID for the source archive where this data type originated.
	 * @param sourceDataTypeID the ID of the associated data type in the source archive.
	 * @param lastChangeTime the time this data type was last changed.
	 * @return the database record for this data type.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract DBRecord createRecord(String name, String comments, long categoryID, long returnDtID,
			boolean hasNoReturn, boolean hasVarArgs, byte callingConventionID, long sourceArchiveID,
			long sourceDataTypeID, long lastChangeTime) throws IOException;

	/**
	 * Gets a function signature definition data type record from the database based on its ID.
	 * @param functionDefID the data type's ID.
	 * @return the record for the function definition data type.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract DBRecord getRecord(long functionDefID) throws IOException;

	/**
	 * Gets an iterator over all function signature definition data type records.
	 * @return the function definition data type record iterator.
	 * @throws IOException if the database can't be accessed.
	 */
	@Override
	public abstract RecordIterator getRecords() throws IOException;

	/**
	 * Removes the function definition data type record with the specified ID.
	 * @param functionDefID the ID of the data type.
	 * @return true if the record is removed.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract boolean removeRecord(long functionDefID) throws IOException;

	/**
	 * Updates the function definition data type table with the provided record.
	 * @param record the new record
	 * @param setLastChangeTime true means change the last change time in the record to the
	 * current time before putting the record in the database.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract void updateRecord(DBRecord record, boolean setLastChangeTime) throws IOException;

	/**
	 * Deletes the function definition data type table from the database with the specified database handle.
	 * @param handle handle to the database where the table should get deleted.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract void deleteTable(DBHandle handle) throws IOException;

	/**
	 * Gets all the function definition data types that are contained in the category that has the indicated ID.
	 * @param categoryID the category whose function definition data types are wanted.
	 * @return an array of IDs for the function definition data types in the category.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract Field[] getRecordIdsInCategory(long categoryID) throws IOException;

	/**
	 * Gets an array with the IDs of all data types in the function definition table that were derived
	 * from the source data type archive indicated by the source archive ID.
	 * @param archiveID the ID of the source archive whose data types we want.
	 * @return the array data type IDs.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract Field[] getRecordIdsForSourceArchive(long archiveID) throws IOException;

	/**
	 * Get function definition record whose sourceID and datatypeID match the specified Universal IDs.
	 * @param sourceID universal source archive ID
	 * @param datatypeID universal datatype ID
	 * @return function definition record found or null
	 * @throws IOException if IO error occurs
	 */
	abstract DBRecord getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID)
			throws IOException;

	/**
	 * Determine if the calling convention ID within record reflects a Generic Calling Convention 
	 * ordinal (i.e., true if V1 adapter in use for read-only mode).  
	 * See {@link #getGenericCallingConventionName(int)} for Generic Calling Convention name lookup.
	 * @return true if calling convention ID within record reflects a Generic Calling Convention 
	 * ordinal.
	 */
	boolean usesGenericCallingConventionId() {
		return false;
	}

	/**
	 * Get old GenericCallingConvention name for specified ordinal value.
	 * @param ordinal old GenericCallingConvention ordinal
	 * @return old GenericCallingConvention name
	 */
	static String getGenericCallingConventionName(int ordinal) {
		GenericCallingConvention genericCallingConvention = GenericCallingConvention.get(ordinal);
		return genericCallingConvention != GenericCallingConvention.unknown
				? genericCallingConvention.getDeclarationName()
				: CompilerSpec.CALLING_CONVENTION_unknown;
	}

}
