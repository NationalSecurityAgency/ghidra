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

import db.DBRecord;
import db.RecordIterator;

/**
 *
 * Adapter to access the Tree database table that has a Tree ID (key) and
 * a tree name.
 * 
 * 
 */
interface TreeDBAdapter {

	/**
	 * Create a new record for Tree table.
	 * @param name name of the tree 
	 * @return record for the tree
	 * @throws IOException if there was a problem accessing the database
	 */
	DBRecord createRecord(String name) throws IOException;

	/**
	 * Delete the record for the tree and all associated tables.
	 * @param treeID key
	 * @return true if the tree was successfully deleted
	 * @throws IOException if there was a problem accessing the database
	 */
	boolean deleteRecord(long treeID) throws IOException;

	/**
	 * Get the record for the given tree ID.
	 * @throws IOException if there was a problem accessing the database
	 */
	DBRecord getRecord(long treeID) throws IOException;

	/**
	 * Get the record for the tree with the given name. 
	 * @throws IOException if there was a problem accessing the database
	 */
	DBRecord getRecord(String name) throws IOException;

	/**
	 * Get an iterator over all tree records. 
	 * @throws IOException if there was a problem accessing the database
	 */
	RecordIterator getRecords() throws IOException;

	/**
	 * Update the tree table with the given record.  
	 * @throws IOException if there was a problem accessing the database
	 */
	void updateRecord(DBRecord record) throws IOException;
}
