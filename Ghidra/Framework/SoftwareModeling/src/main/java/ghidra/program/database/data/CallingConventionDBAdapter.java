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
import java.util.Set;
import java.util.function.Consumer;

import db.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access the Function Calling Conventions tables.
 */
abstract class CallingConventionDBAdapter {

	static final byte UNKNOWN_CALLING_CONVENTION_ID = (byte) 0;
	static final byte DEFAULT_CALLING_CONVENTION_ID = (byte) 1;
	static final byte FIRST_CALLING_CONVENTION_ID = (byte) 2;

	static final String CALLING_CONVENTION_TABLE_NAME = "Calling Conventions";

	static final Schema CALLING_CONVENTION_SCHEMA =
		CallingConventionDBAdapterV0.V0_CALLING_CONVENTION_SCHEMA;
	// Calling Convention Columns
	static final int CALLING_CONVENTION_NAME_COL =
		CallingConventionDBAdapterV0.V0_CALLING_CONVENTION_NAME_COL;

	/**
	 * Gets an adapter for working with the calling convention database table.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param tablePrefix prefix to be used with default table name
	 * @param monitor task monitor
	 * @return adapter instance
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there is a problem accessing the database.
	 * @throws CancelledException if task is cancelled
	 */
	static CallingConventionDBAdapter getAdapter(DBHandle handle, int openMode, String tablePrefix,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {
		if (openMode == DBConstants.CREATE) {
			return new CallingConventionDBAdapterV0(handle, tablePrefix, true);
		}
		try {
			return new CallingConventionDBAdapterV0(handle, tablePrefix, false);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			CallingConventionDBAdapter adapter = findReadOnlyAdapter(handle);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter, tablePrefix, monitor);
			}
			return adapter;
		}
	}

	private static CallingConventionDBAdapter findReadOnlyAdapter(DBHandle handle) {
		return new CallingConventionDBAdapterNoTable();
	}

	private static CallingConventionDBAdapter upgrade(DBHandle handle,
			CallingConventionDBAdapter oldAdapter, String tablePrefix, TaskMonitor monitor)
			throws VersionException, IOException {
		return new CallingConventionDBAdapterV0(handle, tablePrefix, true);
	}

	/**
	 * Get (and assign if needed thus requiring open transaction) the ID associated with the 
	 * specified calling convention name.  If name is a new convention and the number of stored
	 * convention names exceeds 127 the returned ID will correspond to the unknown calling 
	 * convention.
	 * @param name calling convention name or null if unknown
	 * @param conventionAdded callback when new calling convention is added
	 * @return calling convention ID
	 * @throws IOException if an IO error occurs
	 */
	abstract byte getCallingConventionId(String name, Consumer<String> conventionAdded)
			throws IOException;

	/**
	 * Get calling convention name which corresponds to the specified id.
	 * @param id calling convention storage ID
	 * @return calling convention name or null if unknown call convention
	 * @throws IOException if IO error occurs
	 */
	abstract String getCallingConventionName(byte id) throws IOException;

	/**
	 * Clear calling convention cached lookup maps
	 */
	abstract void invalidateCache();

	/**
	 * Get all stored calling convention names.  The "default" and "unknown" 
	 * names are excluded from this set.
	 * @return set of all stored calling convention names
	 * @throws IOException if an IO error occurs
	 */
	abstract Set<String> getCallingConventionNames() throws IOException;

}
