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
package ghidra.program.model.data;

import java.util.List;

import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Each data type resides in a given a category.
 */
public interface Category extends Comparable<Category> {
	/**
	 * Get the name of this category.
	 */
	public abstract String getName();

	/**
	 * Sets the name of this category.
	 * @param name the new name for this category
	 * @throws DuplicateNameException if another category exists in the same parent with the same name;
	 * @throws InvalidNameException if the name is not an acceptable name.
	 */
	public abstract void setName(String name) throws DuplicateNameException, InvalidNameException;

	/**
	 * Get all categories in this category.
	 * @return zero-length array if there are no categories
	 */
	public abstract Category[] getCategories();

	/**
	 * Get all data types in this category.
	 * @return zero-length array if there are no data types
	 */
	public abstract DataType[] getDataTypes();

	/**
	 * Get all data types in this category whose base name matches the base name of the given name.
	 * The base name of a name is the first part of the string up to where the first ".conflict"
	 * occurs. In other words, finds all data types whose name matches the given name once
	 * any conflict suffixes have been removed from both the given name and the data types
	 * that are being scanned. 
	 * @param name the name for which to get conflict related data types in this category. Note: the
	 * name that is passed in will be normalized to its base name, so you may pass in names with .conflict
	 * appended as a convenience.
	 * @return a list of data types that have the same base name as the base name of the given name
	 */
	public abstract List<DataType> getDataTypesByBaseName(String name);

	/**
	 * Adds the given datatype to this category.
	 * @param dt the datatype to add to this category.
	 * @param handler the DataTypeConflictHandler to use if conflicts are discovered.
	 * @return the new datatype with its category path adjusted.
	 */
	public abstract DataType addDataType(DataType dt, DataTypeConflictHandler handler);

	/**
	 * Get a category with the given name.
	 * @param name the name of the category
	 * @return null if there is no category by this name
	 */
	public abstract Category getCategory(String name);

	/**
	 * return the full CategoryPath for this category.
	 * @return the full CategoryPath for this category.
	 */
	public abstract CategoryPath getCategoryPath();

	/**
	 * Get a data type with the given name.
	 * @param name the name of the data type
	 * @return null if there is no data type by this name
	 */
	public abstract DataType getDataType(String name);

	/**
	 * Create a category with the given name; if category already exists, then
	 * return that category.
	 * @param name the category name
	 * @throws InvalidNameException if name has invalid characters
	 */
	public abstract Category createCategory(String name) throws InvalidNameException;

	/**
	 * Remove the named category from this category.
	 * @param name the name of the category to remove
	 * @param monitor the task monitor
	 * @return true if the category was removed
	 */
	public abstract boolean removeCategory(String name, TaskMonitor monitor);

	/**
	 * Remove the named category from this category, IFF it is empty.
	 * @param name the name of the category to remove
	 * @param monitor the task monitor
	 * @return true if the category was removed
	 */
	public abstract boolean removeEmptyCategory(String name, TaskMonitor monitor);

	/**
	 * Move the given category to this category; category is removed from
	 * its original parent category.
	 * @param category the category to move
	 * @throws DuplicateNameException if this category already contains a
	 * category or data type with the same name as the category param.
	 */
	public abstract void moveCategory(Category category, TaskMonitor monitor)
			throws DuplicateNameException;

	/**
	 * Make a new subcategory from the given category.
	 * @param category the category to copy into this category
	 * @return category that is added to this category
	 */
	public abstract Category copyCategory(Category category, DataTypeConflictHandler handler,
			TaskMonitor monitor);

	/**
	 * Return this category's parent; return null if this is the root category.
	 */
	public abstract Category getParent();

	/**
	 * Returns true if this is the root category.
	 * @return true if this is the root category.
	 */
	public abstract boolean isRoot();

	/**
	 * Get the fully qualified name for this category.
	 */
	public abstract String getCategoryPathName();

	/**
	 * Get the root category.
	 */
	public abstract Category getRoot();

	/**
	 * Get the data type manager associated with this category.
	 */
	public abstract DataTypeManager getDataTypeManager();

	/**
	 * Move a data type into this category
	 *
	 * @param type data type to be moved
	 * @param handler the handler to call if there is a data type conflict
	 * @throws DataTypeDependencyException
	 */
	public abstract void moveDataType(DataType type, DataTypeConflictHandler handler)
			throws DataTypeDependencyException;

	/**
	 * Remove a datatype from this category
	 *
	 * @param type data type to be removed
	 * @param monitor monitor of progress in case operation takes a long time.
	 * @return true if the data type was found in this category and successfully removed.
	 */
	public abstract boolean remove(DataType type, TaskMonitor monitor);

	/**
	 * Get the ID for this category.
	 */
	public long getID();
}
