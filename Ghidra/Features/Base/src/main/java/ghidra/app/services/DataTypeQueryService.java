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

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

/**
 * Simplified datatype service interface to provide query capabilities
 * to a set of open datatype managers
 */
public interface DataTypeQueryService {

	/**
	 * Gets the open data type managers.
	 * 
	 * @return the open data type managers.
	 */
	public DataTypeManager[] getDataTypeManagers();

	/**
	 * Gets the sorted list of all datatypes known by this service via it's owned DataTypeManagers.
	 * This method can be called frequently, as the underlying data is indexed and only updated
	 * as changes are made.
	 * @return the sorted list of known data types.
	 */
	public List<DataType> getSortedDataTypeList();

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
	public DataType getDataType(String filterText);

}
