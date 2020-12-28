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
 * Database adapter for managing built-in data types.
 */
public abstract class BuiltinDBAdapter {
	static final Schema SCHEMA = BuiltinDBAdapterV0.V0_SCHEMA;
	static final int BUILT_IN_NAME_COL = BuiltinDBAdapterV0.V0_BUILT_IN_NAME_COL;
	static final int BUILT_IN_CLASSNAME_COL = BuiltinDBAdapterV0.V0_BUILT_IN_CLASSNAME_COL;
	static final int BUILT_IN_CAT_COL = BuiltinDBAdapterV0.V0_BUILT_IN_CAT_COL;

	/**
	 * Gets an adapter for working with the built-in data type database table. The adapter is based 
	 * on the version of the database associated with the specified database handle and the openMode.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param monitor the monitor to use for displaying status or for canceling.
	 * @return the adapter for accessing the table of built-in data types.
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there was a problem accessing the database
	 */
	static BuiltinDBAdapter getAdapter(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, IOException {
		return new BuiltinDBAdapterV0(handle, openMode == DBConstants.CREATE);
	}

	/**
	 * Create a new built in types record.
	 * @param name data type name
	 * @param className class name for data type
	 * @param categoryID ID of the parent category
	 * @return new record
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord createRecord(String name, String className, long categoryID) throws IOException;

	/**
	 * Gets the Built-in data type record with the indicated ID.
	 * @param dataTypeID the data type's ID.
	 * @return the record for the Built-in data type.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getRecord(long dataTypeID) throws IOException;

	/** 
	 * Returns an array containing the data type IDs for the given category ID
	 * @param categoryID category ID
	 * @return an array of the data type IDs as LongFields within Field array; 
	 * empty array if no built-in data types found.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract Field[] getRecordIdsInCategory(long categoryID) throws IOException;

	/**
	 * Update the built-ins table with the given record.
	 * @param record the new record
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void updateRecord(DBRecord record) throws IOException;

	/**
	 * Remove the record with the given dataID.
	 * @param dataID key
	 *  @return true if record was deleted successfully.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract boolean removeRecord(long dataID) throws IOException;

	/**
	 * Returns an iterator over all records for built-in data types.
	 * @return record iterator
	 * @throws IOException if IO error occurs
	 */
	abstract RecordIterator getRecords() throws IOException;
}
