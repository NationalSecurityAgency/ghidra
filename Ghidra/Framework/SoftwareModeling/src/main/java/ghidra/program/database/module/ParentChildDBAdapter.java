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
package ghidra.program.database.module;

import java.io.IOException;

import db.*;
import ghidra.util.exception.VersionException;

abstract class ParentChildDBAdapter {

	private static final String PARENT_CHILD_TABLE_NAME = "Parent/Child Relationships";

	static final int PARENT_ID_COL = ParentChildDBAdapterV0.V0_PARENT_ID_COL;
	static final int CHILD_ID_COL = ParentChildDBAdapterV0.V0_CHILD_ID_COL;
	static final int ORDER_COL = ParentChildDBAdapterV0.V0_ORDER_COL;

	/**
	 * Gets an adapter for working with the  program tree parent/child database table.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param treeID associated program tree ID
	 * @return module table adapter
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if database IO error occurs
	 */
	static ParentChildDBAdapter getAdapter(DBHandle handle, int openMode, long treeID)
			throws VersionException, IOException {
		return new ParentChildDBAdapterV0(handle, openMode == DBConstants.CREATE, treeID);
	}

	static final String getTableName(long treeID) {
		return PARENT_CHILD_TABLE_NAME + treeID;
	}

	/**
	 * Add parent/child record
	 * @param parentModuleID parent module ID
	 * @param childId child ID.  Module ID are positive, fragment IDs must be negative.
	 * @return parent/child record
	 * @throws IOException if database IO error occurs
	 */
	abstract DBRecord addParentChildRecord(long parentModuleID, long childId) throws IOException;

	/**
	 * Get parent/child record
	 * @param parentID parent module ID
	 * @param childID childId child ID.  Module ID are positive, fragment IDs must be negative.
	 * @return parent/child record or null if not found
	 * @throws IOException if database IO error occurs
	 */
	abstract DBRecord getParentChildRecord(long parentID, long childID) throws IOException;

	/**
	 * Get parent/child record for specified record key
	 * @param key parent/child record key
	 * @return parent/child record or null if not found
	 * @throws IOException if database IO error occurs
	 */
	abstract DBRecord getParentChildRecord(long key) throws IOException;

	/**
	 * Update parent/child record
	 * @param record parent/child record
	 * @throws IOException if database IO error occurs
	 */
	abstract void updateParentChildRecord(DBRecord record) throws IOException;

	/**
	 * Remove parent/child record
	 * @param key record key
	 * @return true if deleted else false if not found
	 * @throws IOException if database IO error occurs
	 */
	abstract boolean removeParentChildRecord(long key) throws IOException;

	/**
	 * Get the parent/child record keys which correspond to those records
	 * containing the specified parent or child id as determined by the 
	 * specified index column
	 * @param id parent or child id as determined by indexCol
	 * @param indexCol {@link #CHILD_ID_COL} or {@link #PARENT_ID_COL}
	 * @return parent/child record keys
	 * @throws IOException if database IO error occurs
	 */
	abstract Field[] getParentChildKeys(long id, int indexCol) throws IOException;

}
