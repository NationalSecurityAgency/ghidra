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
/*
 *
 */
package ghidra.program.database.data;

import java.io.IOException;

import db.DBHandle;
import db.Record;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

abstract class CategoryDBAdapter {
	static final int CATEGORY_NAME_COL = CategoryDBAdapterV0.V0_CATEGORY_NAME_COL;
	static final int CATEGORY_PARENT_COL = CategoryDBAdapterV0.V0_CATEGORY_PARENT_COL;

	static CategoryDBAdapter getAdapter(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, IOException {
		return new CategoryDBAdapterV0(handle, openMode);
	}

	/**
	 * Gets the category record for the given ID.
	 * @param categoryID the key into the category table
	 * @return the record for the given ID or null if no record with that id exists.
	 */
	abstract Record getRecord(long categoryID) throws IOException;

	/**
	 * Updates the record in the database
	 * @param categoryID
	 * @param parentCategoryID
	 * @param name
	 * @throws IOException
	 */
	abstract void updateRecord(long categoryID, long parentCategoryID, String name)
			throws IOException;

	/**
	 * Returns a list of categoryIDs that have the given parent ID.
	 * @param categoryID the key into the category table
	 * @return an array of categoryIDs that have the specified parent
	 */
	abstract long[] getRecordIdsWithParent(long categoryID) throws IOException;

	/**
	 * Creates a new category with the given name and parent ID.
	 * @param name the name of the new category.
	 * @param categoryID the key into the category table
	 * @return a new record for the new category.
	 */
	abstract Record createCategory(String name, long parentID) throws IOException;

	/**
	 * Removes the category with the given ID.
	 * @param categoryID the key into the category table
	 * @return true if the a category with that id existed.
	 */
	abstract boolean removeCategory(long categoryID) throws IOException;

	/**
	 * Get the record for the root category.
	 */
	abstract Record getRootRecord() throws IOException;

	abstract void putRecord(Record record) throws IOException;

	abstract int getRecordCount();
}
