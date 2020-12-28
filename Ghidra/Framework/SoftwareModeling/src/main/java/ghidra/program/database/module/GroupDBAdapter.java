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

import db.Field;
import db.DBRecord;
import ghidra.util.exception.DuplicateNameException;

/**
 * Adapter to access the module, fragment, and parent/child database tables.
 * 
 * 
 */
interface GroupDBAdapter {

	/**
	 * Create the root module for a tree; the module ID for the root is 0.
	 * @param name the name of the program.
	 * @return record for the root module; should never be null
	 * @throws IOException if there was a problem accessing the database
	 */
	DBRecord createRootModule(String name) throws IOException;

	/**
	 * Create a new module.
	 * @param parentModuleID ID of parent module
	 * @param name module name
	 * @return record for the module
	 * @throws IOException if there was a problem accessing the database
	 * @throws DuplicateNameException if a module or fragment already exists
	 * having the given name
	 */
	DBRecord createModule(long parentModuleID, String name)
			throws IOException, DuplicateNameException;

	/**
	 * Get the record for the module with the given key.
	 * @param module ID 
	 * @return record for the module; null if the record was not found
	 * @throws IOException if there was a problem accessing the database
	 */
	DBRecord getModuleRecord(long moduleID) throws IOException;

	/**
	 * Get the module record with the given name.
	 * @param name module name
	 * @return module record; null if no module exists with the given name
	 * @throws IOException if there was a problem accessing the database
	 */
	DBRecord getModuleRecord(String name) throws IOException;

	/**
	 * Update the module table with the given record.
	 * @throws IOException if there was a problem accessing the database
	 */
	void updateModuleRecord(DBRecord record) throws IOException;

	/**
	 * Create a new fragment
	 * @param parentModuleID ID of parent module
	 * @param name fragment name
	 * @return record for the fragment
	 * @throws IOException if there was a problem accessing the database
	 * @throws DuplicateNameException if a module or fragment already exists
	 * having the given name
	 */
	DBRecord createFragment(long parentModuleID, String name)
			throws IOException, DuplicateNameException;

	/**
	 * Get the record for the fragment with the given key.
	 * @param fragID
	 * @return
	 * @throws IOException if there was a problem accessing the database
	 */
	DBRecord getFragmentRecord(long fragID) throws IOException;

	/**
	 * Get the fragment record with the given name.
	 * @param name fragment name
	 * @return fragment record; null if no fragment exists with the given
	 * name
	 * @throws IOException if there was a problem accessing the database
	 */
	DBRecord getFragmentRecord(String name) throws IOException;

	/**
	 * Update the fragment table with the given record.
	 * @throws IOException if there was a problem accessing the database
	 */
	void updateFragmentRecord(DBRecord record) throws IOException;

	/**
	 * Get the record in the Parent/Child table.
	 * @param parentID module ID of the parent
	 * @param childID childID
	 * @return record; null if the record was not found
	 * @throws IOException if there was a problem accessing the database
	 */
	DBRecord getParentChildRecord(long parentID, long childID) throws IOException;

	/**
	 * Get the keys in the Parent/Child table that are indexed on the given
	 * indexed column and have the value of ID.
	 * @param ID value of indexed column
	 * @param indexedCol column that is indexed in the table to do the lookup
	 * @return zero-length array if no records were found
	 * @throws IOException if there was a problem accessing the database
	 */
	Field[] getParentChildKeys(long ID, int indexedCol) throws IOException;

	/**
	 * Get the Parent/Child record with the given key.
	 * @return record or null if the record does not exist
	 * @throws IOException if there was a problem accessing the database
	 */
	DBRecord getParentChildRecord(long key) throws IOException;

	/**
	 * Create a new Parent/Child record.
	 * @param parentID module ID of the parent
	 * @param childID ID for the child
	 * @return record or nul if the record does not exist
	 * @throws IOException if there was a problem accessing the database
	 */
	DBRecord addParentChildRecord(long parentID, long childID) throws IOException;

	/**
	 * Remove the record with the given key in the Parent/Child table.
	 * @return true if the record was deleted
	 * @throws IOException if there was a problem accessing the database
	 */
	boolean removeParentChildRecord(long key) throws IOException;

	/**
	 * Update the Parent/Child table with the given record.
	 * @throws IOException if there was a problem accessing the database
	 */
	void updateParentChildRecord(DBRecord record) throws IOException;

	/**
	 * Remove the fragment record.
	 * @param childID
	 * @throws IOException if there was a problem accessing the database
	 */
	boolean removeFragmentRecord(long childID) throws IOException;

	/**
	 * Remove the module record.
	 * @param childID
	 * @return true if the record was removed
	 * @throws IOException if there was a problem accessing the database
	 */
	boolean removeModuleRecord(long childID) throws IOException;
}
