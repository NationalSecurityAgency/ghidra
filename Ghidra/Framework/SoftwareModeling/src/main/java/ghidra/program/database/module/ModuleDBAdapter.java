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
package ghidra.program.database.module;

import java.io.IOException;

import db.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

abstract class ModuleDBAdapter {

	private static final String MODULE_TABLE_NAME = "Module Table";

	static final int MODULE_NAME_COL = ModuleDBAdapterV1.V1_MODULE_NAME_COL;
	static final int MODULE_COMMENTS_COL = ModuleDBAdapterV1.V1_MODULE_COMMENTS_COL;
	static final int MODULE_CHILD_COUNT_COL = ModuleDBAdapterV1.V1_MODULE_CHILD_COUNT_COL;

	/**
	 * Gets an adapter for working with the  program tree module database table.
	 * @param moduleMgr module manager for corresponding program tree.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param monitor task monitor
	 * @return module table adapter
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there is a problem accessing the database.
	 * @throws CancelledException if task cancelled
	 */
	static ModuleDBAdapter getAdapter(ModuleManager moduleMgr, int openMode, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		long treeID = moduleMgr.getTreeID();
		DBHandle handle = moduleMgr.getDatabaseHandle();
		try {
			return new ModuleDBAdapterV1(handle, openMode == DBConstants.CREATE, treeID);
		}
		catch (VersionException e) {
			// V0 read-only is slow - force upgrade
			if (!e.isUpgradable() || openMode != DBConstants.UPGRADE) {
				throw e;
			}
			ModuleDBAdapter adapter = findReadOnlyAdapter(moduleMgr);
			return upgrade(moduleMgr, adapter, monitor);
		}
	}

	private static ModuleDBAdapter upgrade(ModuleManager moduleMgr, ModuleDBAdapter oldAdapter,
			TaskMonitor monitor) throws IOException, CancelledException {
		long treeID = moduleMgr.getTreeID();
		DBHandle handle = moduleMgr.getDatabaseHandle();
		DBHandle tmpHandle = new DBHandle();
		long id = tmpHandle.startTransaction();
		ModuleDBAdapter tmpAdapter = null;
		try {
			tmpAdapter = new ModuleDBAdapterV1(tmpHandle, true, treeID);
			RecordIterator it = oldAdapter.getRecords();
			while (it.hasNext()) {
				monitor.checkCancelled();
				DBRecord rec = it.next();
				tmpAdapter.updateModuleRecord(rec);
			}
			handle.deleteTable(getTableName(treeID));

			ModuleDBAdapter newAdapter = new ModuleDBAdapterV1(handle, true, treeID);
			it = tmpAdapter.getRecords();
			while (it.hasNext()) {
				monitor.checkCancelled();
				DBRecord rec = it.next();
				newAdapter.updateModuleRecord(rec);
			}
			return newAdapter;
		}
		catch (VersionException e) {
			throw new RuntimeException(e); // unexpected exception
		}
		finally {
			tmpHandle.endTransaction(id, true);
			tmpHandle.close();
		}
	}

	private static ModuleDBAdapter findReadOnlyAdapter(ModuleManager moduleMgr)
			throws VersionException, IOException {

		long treeID = moduleMgr.getTreeID();
		DBHandle handle = moduleMgr.getDatabaseHandle();
		ParentChildDBAdapter parentChildAdapter = moduleMgr.getParentChildAdapter();

		return new ModuleDBAdapterV0(handle, treeID, parentChildAdapter);
	}

	static final String getTableName(long treeID) {
		return MODULE_TABLE_NAME + treeID;
	}

	abstract DBRecord createModuleRecord(long parentModuleID, String name) throws IOException;

	abstract DBRecord getModuleRecord(long key) throws IOException;

	abstract DBRecord getModuleRecord(String name) throws IOException;

	abstract RecordIterator getRecords() throws IOException;

	abstract void updateModuleRecord(DBRecord record) throws IOException;

	abstract boolean removeModuleRecord(long childID) throws IOException;

}
