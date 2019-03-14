/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.model.listing;

import ghidra.framework.model.ChangeSet;

/**
 * Interface for a Data Type Change set.  Objects that implements this interface track
 * various change information on a data type manager.
 */
public interface DataTypeChangeSet extends ChangeSet {

	//
	// Data Types
	//
	/**
	 * Adds the dataType ID to the list of changed data types.
	 */
	void dataTypeChanged(long id);
	
	/**
	 * Adds the data type ID to the list of added data types.
	 * @param id
	 */
	void dataTypeAdded(long id);
	
	/**
	 * returns a list of data type IDs that have changed.
	 */
	long[] getDataTypeChanges();
	
	/**
	 * returns a list of data type IDs that have been added.
	 */
	long[] getDataTypeAdditions();

	
	//
	// Data Type Categories
	//
	/**
	 * adds the data type category id to the list of categories that have changed.
	 */
	void categoryChanged(long id);
	
	/**
	 * adds the data type category id to the list of categories that have been added.
	 */
	void categoryAdded(long id);
	
	/**
	 * returns the list of category IDs that have changed.
	 */
	long[] getCategoryChanges();
	
	/**
	 * returns the list of category IDs that have been added.
	 */
	long[] getCategoryAdditions();
	
	//
	// Data Type Source Archive IDs
	//
	/**
	 * Adds the data type source archive ID to the list of changed data type archive IDs.
	 */
	void sourceArchiveChanged(long id);
	
	/**
	 * Adds the data type source archive ID to the list of added data type archive IDs.
	 * @param id the data type source archive ID
	 */
	void sourceArchiveAdded(long id);
	
	/**
	 * returns a list of data type source archive IDs that have changed.
	 */
	long[] getSourceArchiveChanges();
	
	/**
	 * returns a list of data type source archive IDs that have been added.
	 */
	long[] getSourceArchiveAdditions();

	
}
