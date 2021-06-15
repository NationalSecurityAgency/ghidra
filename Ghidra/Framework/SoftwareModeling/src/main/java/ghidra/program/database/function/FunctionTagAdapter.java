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
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * This represents a table that stores all possible function tags available for use.
 * The table consists of two columns: one for the tag name, and one indicating
 * whether this tag is modifiable.
 * 
 * Non-modifiable tags cannot be deleted or edited by any user. These are typically
 * tags that have been pre-loaded via some external mechanism and need to be 
 * preserved as originally defined.
 */
abstract class FunctionTagAdapter {

	static final String TABLE_NAME = "Function Tags";

	static final int CURRENT_VERSION = 0;

	static final int NAME_COL = 0;
	static final int COMMENT_COL = 1;

	/**
	 * 
	 * @param handle database handle
	 * @param openMode CREATE, UPDATE, UPGRADE
	 * @param monitor task monitor
	 * @return
	 * @throws VersionException
	 * @throws CancelledException
	 * @throws IOException
	 */
	static FunctionTagAdapter getAdapter(DBHandle handle, int openMode,
			TaskMonitor monitor) throws VersionException, CancelledException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new FunctionTagAdapterV0(handle, true);
		}
		try {
			return new FunctionTagAdapterV0(handle, false);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			FunctionTagAdapter adapter = findReadOnlyAdapter(handle);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter, monitor);
			}
			return adapter;
		}
	}

	private static FunctionTagAdapter findReadOnlyAdapter(DBHandle handle) {
		return null;
	}

	private static FunctionTagAdapter upgrade(DBHandle handle,
			FunctionTagAdapter oldAdapter,
			TaskMonitor monitor)
			throws VersionException {
		return new FunctionTagAdapterV0(handle, true);
	}

	/**
	 * Returns all tag records in the database.
	 * 
	 * @return list of tags
	 * @throws IOException
	 */
	abstract RecordIterator getRecords() throws IOException;

	/**
	 * Returns a record matching the given tag name, or null if not found.
	 * 
	 * @param tag the tag name
	 * @return Record, or null if not found
	 * @throws IOException
	 */
	abstract DBRecord getRecord(String tag) throws IOException;

	/**
	 * Returns the tag record with the given id.
	 * 
	 * @param id the tag index
	 * @return Record, or null if not found
	 * @throws IOException
	 */
	abstract DBRecord getRecord(long id) throws IOException;

	/**
	 * Creates a {@link DBRecord} with the given tag name.
	 * 
	 * @param tag the tag name to create
	 * @param comment tag comment
	 * @return
	 * @throws IOException
	 */
	abstract DBRecord createTagRecord(String tag, String comment) throws IOException;

	/**
	 * Updates the database record for a tag.
	 * @param record tag record
	 * @throws IOException
	 */
	abstract void updateRecord(DBRecord record) throws IOException;
	
	/**
	 * Removes the tag with the given name from the database.
	 * 
	 * @param id tag id
	 * @throws IOException
	 */
	abstract void removeTagRecord(long id) throws IOException;

	/**
	 * Returns the total number of tags in the database.
	 * 
	 * @return the number of tags
	 */
	abstract int getNumTags();
}
