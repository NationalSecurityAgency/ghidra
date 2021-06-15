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
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access the Component database table.
 */
abstract class ComponentDBAdapter {

	static final String COMPONENT_TABLE_NAME = "Component Data Types";
	static final Schema COMPONENT_SCHEMA = ComponentDBAdapterV0.V0_COMPONENT_SCHEMA;

	static final int COMPONENT_PARENT_ID_COL = ComponentDBAdapterV0.V0_COMPONENT_PARENT_ID_COL;
	static final int COMPONENT_OFFSET_COL = ComponentDBAdapterV0.V0_COMPONENT_OFFSET_COL;
	static final int COMPONENT_DT_ID_COL = ComponentDBAdapterV0.V0_COMPONENT_DT_ID_COL;
	static final int COMPONENT_FIELD_NAME_COL = ComponentDBAdapterV0.V0_COMPONENT_FIELD_NAME_COL;
	static final int COMPONENT_COMMENT_COL = ComponentDBAdapterV0.V0_COMPONENT_COMMENT_COL;
	static final int COMPONENT_SIZE_COL = ComponentDBAdapterV0.V0_COMPONENT_SIZE_COL;
	static final int COMPONENT_ORDINAL_COL = ComponentDBAdapterV0.V0_COMPONENT_ORDINAL_COL;

	/**
	 * Gets an adapter for working with the component data type database table. Components are 
	 * used to specify the individual elements of a composite data type. The adapter is based 
	 * on the version of the database associated with the specified database handle and the openMode.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param monitor the monitor to use for displaying status or for canceling.
	 * @return the adapter for accessing the table of component data types.
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there is a problem accessing the database.
	 */
	static ComponentDBAdapter getAdapter(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, IOException {
		return new ComponentDBAdapterV0(handle, openMode == DBConstants.CREATE);
	}

	/**
	 * Creates a database record for a component data type (an individual member of a composite data type).
	 * @param dataTypeID the ID of the data type for this component.
	 * @param parentID the ID of the data type that this component is a part of.
	 * @param length the total length of this component.
	 * @param ordinal the component's ordinal.
	 * @param offset the component's offset.
	 * @param name the component's name.
	 * @param comment a comment about this component
	 * @return the component data type record.
	 * @throws IOException if there is a problem accessing the database.
	 */
	abstract DBRecord createRecord(long dataTypeID, long parentID, int length, int ordinal,
			int offset, String name, String comment) throws IOException;

	/**
	 * Gets the record for the indicated component data type.
	 * @param componentID the ID of the component data type to retrieve.
	 * @return the component record
	 * @throws IOException if there is a problem accessing the database.
	 */
	abstract DBRecord getRecord(long componentID) throws IOException;

	/**
	 * Removes the component data type record with the specified ID.
	 * @param componentID the ID of the component data type.
	 * @return true if the record is removed.
	 * @throws IOException if there is a problem accessing the database.
	 */
	abstract boolean removeRecord(long componentID) throws IOException;

	/**
	 * Updates the component data type table with the provided record.
	 * @param record the new record
	 * @throws IOException if there is a problem accessing the database.
	 */
	abstract void updateRecord(DBRecord record) throws IOException;

	/**
	 * Gets an array with all of the IDs of the defined components within the composite data type indicated.
	 * @param compositeID the ID of the composite data type whose components are desired.
	 * @return an array of the defined component IDs as LongField values within Field array.
	 * @throws IOException if there is a problem accessing the database.
	 */
	abstract Field[] getComponentIdsInComposite(long compositeID) throws IOException;
}
