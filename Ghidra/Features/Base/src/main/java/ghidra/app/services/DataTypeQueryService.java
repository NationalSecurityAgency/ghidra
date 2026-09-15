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
package ghidra.app.services;

import java.util.List;

import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.*;
import ghidra.util.task.TaskMonitor;

/**
 * Simplified datatype service interface to provide query capabilities to a set of open datatype 
 * managers.
 * 
 * @see DataTypeUtilities
 * @see DataTypeManagerService
 */
public interface DataTypeQueryService {

	/**
	 * Gets the sorted list of all datatypes known by this service via it's owned DataTypeManagers.
	 * This method can be called frequently, as the underlying data is indexed and only updated
	 * as changes are made.  The sorting of the list is done using the {@link DataTypeComparator} 
	 * whose primary sort is based upon the {@link DataTypeNameComparator}.
	 * 
	 * @return the sorted list of known data types.
	 */
	public List<DataType> getSortedDataTypeList();

	/**
	 * Prompts the user for a data type.  The optional filter text will be used to filter the tree
	 * of available types.
	 * Gets the sorted list of all category paths known by this service via its owned 
	 * DataTypeManagers.  This method can be called frequently, as the underlying data is indexed 
	 * and only updated as changes are made.  The sorting of the list is done using the 
	 * natural sort of the {@link CategoryPath} objects.
	 * 
	 * @return the sorted list of known category paths.
	 */
	public List<CategoryPath> getSortedCategoryPathList();

	/**
	 * This method simply calls {@link #promptForDataType(String)}
	 * @deprecated use {@link #promptForDataType(String)}
	 */
	@SuppressWarnings("javadoc")
	@Deprecated(since = "12.0", forRemoval = true)
	public DataType getDataType(String filterText);

	/**
	 * Obtain the preferred datatype which corresponds to the specified 
	 * datatype specified by filterText.  A tool-based service provider
	 * may prompt the user to select a datatype if more than one possibility
	 * exists.
	 * 
	 * @param filterText If not null, this text filters the visible data types to only show those
	 *                   that start with the given text
	 * @return the preferred data type (e.g., chosen by the user) or null if no match found 
	 * or selection was cancelled by user.
	 */
	public DataType promptForDataType(String filterText);

	/**
	 * Finds all data types matching the given name.   This method will search all open data type
	 * archives.
	 * <p>
	 * Unlike {@link DataTypeManagerService#findDataTypes(String, TaskMonitor)}, this method will
	 * not return {@code .conflict} data types.  If you need those types, then you must call each
	 * data type manager directly.
	 * <p>
	 * In the list of types returned, the program data type manager's types will be in the list 
	 * before types from other archives.
	 * 
	 * @param name the data type name to find
	 * @param monitor the task monitor
	 * @return the data types
	 * @see DataTypeManagerService#getDataTypeManagers()
	 */
	public List<DataType> findDataTypes(String name, TaskMonitor monitor);

	/**
	 * Get the data type for the given data type path.
	 * <p>
	 * This method will check each open data type manager for a data type that matches the path.
	 * <p>
	 * If a type is in the program data type manager, then it will be first in the returned list.
	 * 
	 * @param path the path 
	 * @return the data type
	 */
	public List<DataType> getDataTypesByPath(DataTypePath path);

	/**
	 * Get the data type for the given data type path from the program's data type manager.
	 * @param path the path
	 * @return the data type; null if the type does not exist
	 */
	public DataType getProgramDataTypeByPath(DataTypePath path);

}
