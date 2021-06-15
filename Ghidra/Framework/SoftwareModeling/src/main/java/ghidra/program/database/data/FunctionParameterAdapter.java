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
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access the Function Signature Definition Parameters database table.
 */
abstract class FunctionParameterAdapter {

	static final String PARAMETER_TABLE_NAME = "Function Parameters";
	static final Schema PARAMETER_SCHEMA = FunctionParameterAdapterV1.V1_PARAMETER_SCHEMA;

	static final int PARAMETER_PARENT_ID_COL =
		FunctionParameterAdapterV1.V1_PARAMETER_PARENT_ID_COL;
	static final int PARAMETER_DT_ID_COL = FunctionParameterAdapterV1.V1_PARAMETER_DT_ID_COL;
	static final int PARAMETER_NAME_COL = FunctionParameterAdapterV1.V1_PARAMETER_NAME_COL;
	static final int PARAMETER_COMMENT_COL = FunctionParameterAdapterV1.V1_PARAMETER_COMMENT_COL;
	static final int PARAMETER_ORDINAL_COL = FunctionParameterAdapterV1.V1_PARAMETER_ORDINAL_COL;
	static final int PARAMETER_DT_LENGTH_COL =
		FunctionParameterAdapterV1.V1_PARAMETER_DT_LENGTH_COL;

	/**
	 * Gets an adapter for working with the function definition parameters database table. The adapter is based 
	 * on the version of the database associated with the specified database handle and the openMode.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param monitor the monitor to use for displaying status or for canceling.
	 * @return the adapter for accessing the table of function definition parameters.
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there is trouble accessing the database.
	 */
	static FunctionParameterAdapter getAdapter(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, IOException {
		if (openMode == DBConstants.CREATE) {
			return new FunctionParameterAdapterV1(handle, true);
		}
		try {
			return new FunctionParameterAdapterV1(handle, false);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			FunctionParameterAdapter adapter = findReadOnlyAdapter(handle);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter);
			}
			return adapter;
		}
	}

	/**
	 * Tries to get a read only adapter for the database whose handle is passed to this method.
	 * @param handle handle to prior version of the database.
	 * @return the read only Function Definition Parameters table adapter
	 * @throws VersionException if a read only adapter can't be obtained for the database handle's version.
	 */
	static FunctionParameterAdapter findReadOnlyAdapter(DBHandle handle) throws VersionException {
		try {
			return new FunctionParameterAdapterV0(handle);
		}
		catch (VersionException e) {
			if (!e.isUpgradable()) {
				throw e;
			}
		}
		return new FunctionParameterAdapterNoTable(handle);
	}

	/**
	 * Upgrades the Function Definition Parameters table from the oldAdapter's version to the 
	 * current version.
	 * @param handle handle to the database whose table is to be upgraded to a newer version.
	 * @param oldAdapter the adapter for the existing table to be upgraded.
	 * @return the adapter for the new upgraded version of the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if the database can't be read or written.
	 */
	static FunctionParameterAdapter upgrade(DBHandle handle, FunctionParameterAdapter oldAdapter)
			throws VersionException, IOException {

		DBHandle tmpHandle = new DBHandle();
		long id = tmpHandle.startTransaction();
		FunctionParameterAdapter tmpAdapter = null;
		try {
			tmpAdapter = new FunctionParameterAdapterV1(tmpHandle, true);
			RecordIterator it = oldAdapter.getRecords();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				tmpAdapter.updateRecord(rec);
			}
			oldAdapter.deleteTable(handle);
			FunctionParameterAdapterV1 newAdapter = new FunctionParameterAdapterV1(handle, true);
			it = tmpAdapter.getRecords();
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

	/**
	 * Gets an iterator over all function definition parameter data type records.
	 * @return the parameter data type record iterator.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract protected RecordIterator getRecords() throws IOException;

	/**
	 * Delete underlying database table
	 * @param handle database handle
	 * @throws IOException if IO error occurs
	 */
	abstract protected void deleteTable(DBHandle handle) throws IOException;

	/**
	 * Create new parameter definition record
	 * @param dataTypeID parameter datatype ID
	 * @param parentID parent function definition ID
	 * @param ordinal parameter ordinal
	 * @param name parameter name
	 * @param comment parameter comment
	 * @param dtLength datatype length if required, else -1
	 * @return new record
	 * @throws IOException if IO error occurs
	 */
	abstract DBRecord createRecord(long dataTypeID, long parentID, int ordinal, String name,
			String comment, int dtLength) throws IOException;

	/**
	 * Get parameter definition record
	 * @param parameterID parameter record ID
	 * @return parameter definition record or null
	 * @throws IOException if IO error occurs
	 */
	abstract DBRecord getRecord(long parameterID) throws IOException;

	/**
	 * Updates the function definition parameter data type table with the provided record.
	 * @param record the new record
	 * @throws IOException if the database can't be accessed.
	 */
	abstract void updateRecord(DBRecord record) throws IOException;

	/**
	 * Removes the function definition parameter data type record with the specified ID.
	 * @param parameterID the ID of the data type.
	 * @return true if the record is removed.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract boolean removeRecord(long parameterID) throws IOException;

	/**
	 * Get parameter definition IDs for specified function definition
	 * @param functionDefID function definition ID
	 * @return parameter definition IDs as LongField values within Field array
	 * @throws IOException if IO error occurs
	 */
	abstract Field[] getParameterIdsInFunctionDef(long functionDefID) throws IOException;

}
