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

abstract class ProgramTreeDBAdapter {
	
	static final String PROGRAM_TREE_TABLE_NAME = "Trees";
	
	static final int TREE_NAME_COL = ProgramTreeDBAdapterV0.V0_TREE_NAME_COL;
	static final int MODIFICATION_NUM_COL = ProgramTreeDBAdapterV0.V0_MODIFICATION_NUM_COL;
	
	/**
	 * Gets an adapter for working with the  program tree database table.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @return program tree table adapter
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there is a problem accessing the database.
	 */
	static ProgramTreeDBAdapter getAdapter(DBHandle handle, int openMode)
			throws VersionException, IOException {
		return new ProgramTreeDBAdapterV0(handle, openMode == DBConstants.CREATE);
	}

	/**
	 * Create a new record for Tree table.
	 * @param name name of the tree 
	 * @return record for the tree
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord createRecord(String name) throws IOException;

	/**
	 * Delete the record for the specified tree ID.
	 * @param treeID tree record ID
	 * @return true if the tree record was successfully deleted
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract boolean deleteRecord(long treeID) throws IOException;

	/**
	 * Get the record for the given tree ID.
	 * @param treeID tree record ID
	 * @return tree record or null if not found
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getRecord(long treeID) throws IOException;

	/**
	 * Get the record for the tree with the given name. 
	 * @param name tree name
	 * @return tree record or null if not found
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getRecord(String name) throws IOException;

	/**
	 * Get an iterator over all tree records. 
	 * @return record iterator
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getRecords() throws IOException;

	/**
	 * Update the tree table with the given record. 
	 * @param record tree record 
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void updateRecord(DBRecord record) throws IOException;
}
