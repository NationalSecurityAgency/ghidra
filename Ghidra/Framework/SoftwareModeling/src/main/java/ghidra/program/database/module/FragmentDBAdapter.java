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

abstract class FragmentDBAdapter {

	private static final String FRAGMENT_TABLE_NAME = "Fragment Table";

	static final int FRAGMENT_NAME_COL = FragmentDBAdapterV0.V0_FRAGMENT_NAME_COL;
	static final int FRAGMENT_COMMENTS_COL = FragmentDBAdapterV0.V0_FRAGMENT_COMMENTS_COL;

	/**
	 * Gets an adapter for working with the  program tree fragment database table.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param treeID associated program tree ID
	 * @return fragment table adapter
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there is a problem accessing the database.
	 */
	static FragmentDBAdapter getAdapter(DBHandle handle, int openMode, long treeID)
			throws VersionException, IOException {
		return new FragmentDBAdapterV0(handle, openMode == DBConstants.CREATE, treeID);
	}

	static final String getTableName(long treeID) {
		return FRAGMENT_TABLE_NAME + treeID;
	}

	abstract DBRecord createFragmentRecord(long parentModuleID, String name) throws IOException;

	abstract DBRecord getFragmentRecord(long key) throws IOException;

	abstract DBRecord getFragmentRecord(String name) throws IOException;

	abstract void updateFragmentRecord(DBRecord record) throws IOException;

	abstract boolean removeFragmentRecord(long childID) throws IOException;

}
