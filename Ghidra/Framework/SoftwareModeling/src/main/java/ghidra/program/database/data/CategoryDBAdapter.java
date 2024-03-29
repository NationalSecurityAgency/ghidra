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
import ghidra.framework.data.OpenMode;
import ghidra.program.model.data.Category;
import ghidra.util.exception.VersionException;

abstract class CategoryDBAdapter {
	static final int CATEGORY_NAME_COL = CategoryDBAdapterV0.V0_CATEGORY_NAME_COL;
	static final int CATEGORY_PARENT_COL = CategoryDBAdapterV0.V0_CATEGORY_PARENT_COL;

	/**
	 * Gets an adapter for working with the {@link Category} database table.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param tablePrefix prefix to be used with default table name
	 * @return adapter instance
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there is a problem accessing the database.
	 */
	static CategoryDBAdapter getAdapter(DBHandle handle, OpenMode openMode, String tablePrefix)
			throws VersionException, IOException {
		return new CategoryDBAdapterV0(handle, tablePrefix, openMode == OpenMode.CREATE);
	}

	/**
	 * Gets the category record for the given ID.
	 * @param categoryID the key into the category table
	 * @return the record for the given ID or null if no record with that id exists.
	 * @throws IOException if IO error occurs
	 */
	abstract DBRecord getRecord(long categoryID) throws IOException;

	/**
	 * Updates the record in the database
	 * @param categoryID category record key
	 * @param parentCategoryID parent category record key (-1 for root category)
	 * @param name category name
	 * @throws IOException if IO error occurs
	 */
	abstract void updateRecord(long categoryID, long parentCategoryID, String name)
			throws IOException;

	/**
	 * Returns a list of categoryIDs that have the given parent ID.
	 * @param categoryID the key into the catagory table
	 * @return an array of categoryIDs that have the specified parent.  Field array 
	 * returned with LongField key values.
	 * @throws IOException if IO error occurs
	 */
	abstract Field[] getRecordIdsWithParent(long categoryID) throws IOException;

	/**
	 * Creates a new category with the given name and parent ID.
	 * @param name the name of the new category.
	 * @param parentID the parent key into the catagory table
	 * @return a new record for the new category.
	 * @throws IOException if IO error occurs
	 */
	abstract DBRecord createCategory(String name, long parentID) throws IOException;

	/**
	 * Removes the category with the given ID.
	 * @param categoryID the key into the category table
	 * @return true if the a category with that id existed.
	 * @throws IOException if IO error occurs
	 */
	abstract boolean removeCategory(long categoryID) throws IOException;

	/**
	 * Get the record for the root category.
	 * @return root category record
	 * @throws IOException if IO error occurs
	 */
	abstract DBRecord getRootRecord() throws IOException;

	/**
	 * Update record in database
	 * @param record category record
	 * @throws IOException if IO error occurs
	 */
	abstract void putRecord(DBRecord record) throws IOException;

	/**
	 * Get the total number of category records
	 * @return category record count
	 */
	abstract int getRecordCount();
}
