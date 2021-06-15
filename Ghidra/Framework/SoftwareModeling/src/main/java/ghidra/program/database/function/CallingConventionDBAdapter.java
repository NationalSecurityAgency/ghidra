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
package ghidra.program.database.function;

import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import db.*;

/**
 * Adapter to access the Function Calling Conventions tables.
 */
abstract class CallingConventionDBAdapter {
	static final byte UNKNOWN_CALLING_CONVENTION_ID = (byte) 0;
	static final byte DEFAULT_CALLING_CONVENTION_ID = (byte) 1;

	static final Schema CALLING_CONVENTION_SCHEMA =
		CallingConventionDBAdapterV0.V0_CALLING_CONVENTION_SCHEMA;
	// Calling Convention Columns
	static final int CALLING_CONVENTION_NAME_COL =
		CallingConventionDBAdapterV0.V0_CALLING_CONVENTION_NAME_COL;

	static CallingConventionDBAdapter getAdapter(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, IOException {
		if (openMode == DBConstants.CREATE) {
			return new CallingConventionDBAdapterV0(handle, true);
		}
		try {
			return new CallingConventionDBAdapterV0(handle, false);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			CallingConventionDBAdapter adapter = findReadOnlyAdapter(handle);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter);
			}
			return adapter;
		}
	}

	static CallingConventionDBAdapter findReadOnlyAdapter(DBHandle handle) throws IOException {
		try {
			return new CallingConventionDBAdapterV0(handle, false);
		}
		catch (VersionException e) {
		}

		return new CallingConventionDBAdapterNoTable();
	}

	static CallingConventionDBAdapter upgrade(DBHandle handle, CallingConventionDBAdapter oldAdapter)
			throws VersionException, IOException {
		return new CallingConventionDBAdapterV0(handle, true);
	}

	abstract DBRecord createCallingConventionRecord(String name) throws IOException;

	abstract DBRecord getCallingConventionRecord(byte callingConventionID) throws IOException;

	abstract DBRecord getCallingConventionRecord(String name) throws IOException;

}
