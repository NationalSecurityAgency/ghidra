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
package ghidra.program.database.function;

import java.io.IOException;

import db.*;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Database adapter that maps function tags to individual functions. This table 
 * consists of two columns, each of which is an index into the {@link FunctionTagAdapter}
 * and {@link SymbolTable} respectively.
 */
abstract class FunctionTagMappingAdapter {

	static final String TABLE_NAME = "Function Tag Map";

	static final int CURRENT_VERSION = 0;

	static final int FUNCTION_ID_COL = 0;
	static final int TAG_ID_COL = 1;

	static FunctionTagMappingAdapter getAdapter(DBHandle handle, int openMode,
			TaskMonitor monitor) throws VersionException {

		if (openMode == DBConstants.CREATE) {
			return new FunctionTagMappingAdapterV0(handle, true);
		}
		try {
			return new FunctionTagMappingAdapterV0(handle, false);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			FunctionTagMappingAdapter adapter = findReadOnlyAdapter(handle);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter, monitor);
			}
			return adapter;
		}
	}

	private static FunctionTagMappingAdapter findReadOnlyAdapter(DBHandle handle) {
		return new FunctionTagMappingAdapterNoTable(handle);
	}

	private static FunctionTagMappingAdapter upgrade(DBHandle handle,
			FunctionTagMappingAdapter oldAdapter,
			TaskMonitor monitor)
			throws VersionException {
		return new FunctionTagMappingAdapterV0(handle, true);
	}

	/**
	 * Returns all table entries associated with the given function ID. This 
	 * effectively gives a list of all the tags for a function.
	 * 
	 * @param functionID index into the {@link SymbolTable} table
	 * @return iterator of database records
	 * @throws IOException if database error occurs
	 */
	abstract RecordIterator getRecordsByFunctionID(long functionID) throws IOException;

	/**
	 * Searches this table for any entry matching the given function and tag ID. 
	 * 
	 * @param functionID index into the {@link SymbolTable} table
	 * @param tagID index into the {@link FunctionTagAdapter} table
	 * @return null if not found
	 * @throws IOException if database error occurs
	 */
	abstract DBRecord getRecord(long functionID, long tagID) throws IOException;

	/**
	 * Creates a new record with the given function and tag ID's.
	 * 
	 * @param functionID the function's database id
	 * @param tagID the FunctionTags database id
	 * @return newly-created database record
	 * @throws IOException if database error occurs
	 */
	abstract DBRecord createFunctionTagRecord(long functionID, long tagID)
			throws IOException;

	/**
	 * Removes the record with the given function and tag IDs. There should be at most
	 * one of these.
	 * 
	 * @param functionID index into the {@link SymbolTable} table
	 * @param tagID index into the {@link FunctionTagAdapter} table
	 * @return true if the remove was performed
	 * @throws IOException if database error occurs
	 */
	abstract boolean removeFunctionTagRecord(long functionID, long tagID)
			throws IOException;

	/**
	 * Removes all records containing the given tag ID. This should be called
	 * whenever a tag is being deleted from the system.
	 * 
	 * @param tagID index into the {@link FunctionTagAdapter} table
	 * @throws IOException if database error occurs
	 */
	abstract void removeFunctionTagRecord(long tagID) throws IOException;

	/**
	 * Determine if the specified tag ID has been applied to a function
	 * @param id tag ID
	 * @return true if tag applied to one or more functions
	 * @throws IOException if database error occurs
	 */
	abstract boolean isTagAssigned(long id) throws IOException;

	/**
	 * Returns a RecordIterator over all the records in this table
	 * @return  a RecordIterator over all the records in this table
	 * @throws IOException if database error occurs
	 */
	protected abstract RecordIterator getRecords() throws IOException;
}
