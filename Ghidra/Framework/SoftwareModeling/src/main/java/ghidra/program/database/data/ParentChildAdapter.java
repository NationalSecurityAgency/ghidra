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

import db.DBConstants;
import db.DBHandle;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 *
 * Adapter for the custom format table.
 *  
 * 
 * 
 */
abstract class ParentChildAdapter {
	static final String TABLE_NAME = "DT_PARENT_CHILD";

	static ParentChildAdapter getAdapter(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new ParentChildDBAdapterV0(handle, true);
		}
		try {
			return new ParentChildDBAdapterV0(handle, false);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			ParentChildAdapter adapter = findReadOnlyAdapter(handle);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter);
			}
			return adapter;
		}
	}

	static ParentChildAdapter findReadOnlyAdapter(DBHandle handle) {
		return new ParentChildDBAdapterNoTable(handle);
	}

	static ParentChildAdapter upgrade(DBHandle handle, ParentChildAdapter oldAdapter)
			throws VersionException, IOException {

		ParentChildDBAdapterV0 adapter = new ParentChildDBAdapterV0(handle, true);
		adapter.setNeedsInitializing();
		return adapter;
	}

	abstract boolean needsInitializing();

	abstract void createRecord(long parentID, long childID) throws IOException;

	abstract void removeRecord(long parentID, long childID) throws IOException;

	abstract long[] getParentIds(long childID) throws IOException;

	abstract void removeAllRecordsForParent(long parentID) throws IOException;

	abstract void removeAllRecordsForChild(long childID) throws IOException;
}
