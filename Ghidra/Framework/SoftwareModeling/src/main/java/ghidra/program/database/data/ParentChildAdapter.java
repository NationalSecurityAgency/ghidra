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
import java.util.Set;

import db.DBConstants;
import db.DBHandle;
import ghidra.util.exception.VersionException;

/**
 *
 * Adapter for the custom format table.
 *  
 * 
 * 
 */
abstract class ParentChildAdapter {
	static final String PARENT_CHILD_TABLE_NAME = "DT_PARENT_CHILD";

	/**
	 * Gets an adapter for working with the function definition parameters database table.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param tablePrefix prefix to be used with default table name
	 * @return the adapter for accessing the table of function definition parameters.
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there is trouble accessing the database.
	 */
	static ParentChildAdapter getAdapter(DBHandle handle, int openMode, String tablePrefix)
			throws VersionException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new ParentChildDBAdapterV0(handle, tablePrefix, true);
		}
		try {
			return new ParentChildDBAdapterV0(handle, tablePrefix, false);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			ParentChildAdapter adapter = findReadOnlyAdapter(handle);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter, tablePrefix);
			}
			return adapter;
		}
	}

	private static ParentChildAdapter findReadOnlyAdapter(DBHandle handle) {
		return new ParentChildDBAdapterNoTable(handle);
	}

	private static ParentChildAdapter upgrade(DBHandle handle, ParentChildAdapter oldAdapter,
			String tablePrefix) throws VersionException, IOException {

		ParentChildDBAdapterV0 adapter = new ParentChildDBAdapterV0(handle, tablePrefix, true);
		adapter.setNeedsInitializing();
		return adapter;
	}

	abstract boolean needsInitializing();

	abstract void createRecord(long parentID, long childID) throws IOException;

	abstract void removeRecord(long parentID, long childID) throws IOException;

	/**
	 * Get the unique set of parent ID associated with the specified childID.
	 * Since composite parents may have duplicate parent-child records, this method
	 * avoids returning the same parent more than once.
	 * @param childID child datatype ID
	 * @return set of parent datatype IDs
	 * @throws IOException if a DB IO error occurs
	 */
	abstract Set<Long> getParentIds(long childID) throws IOException;

	abstract void removeAllRecordsForParent(long parentID) throws IOException;

	abstract void removeAllRecordsForChild(long childID) throws IOException;
}
