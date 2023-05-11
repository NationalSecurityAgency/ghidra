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
import java.util.*;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ChangeManager;
import ghidra.util.Lock;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Manage the set of trees in the program.
 *
 *
 */
public class TreeManager implements ManagerDB {
	/**
	 * The name of the default tree that is created when a program is created.
	 */
	public final static String DEFAULT_TREE_NAME = "Program Tree";

	private AddressMap addrMap;
	private Map<String, ModuleManager> treeMap; // name mapped to ModuleManager
	private ProgramTreeDBAdapter treeAdapter;
	private ProgramDB program;
	private DBHandle handle;
	private ErrorHandler errHandler;
	private Lock lock;

	/**
	 *
	 * Construct a new TreeManager.
	 *
	 * @param handle database handle
	 * @param errHandler error handler
	 * @param addrMap map to convert addresses to longs and longs to addresses
	 * @param openMode the open mode for the program.
	 * @param lock the program synchronization lock
	 * @param monitor Task monitor for upgrading
	 * @throws IOException if a database io error occurs.
	 * @throws VersionException if the database version is different from the expected version
	 * @throws CancelledException if instantiation has been cancelled
	 */
	public TreeManager(DBHandle handle, ErrorHandler errHandler, AddressMap addrMap, int openMode,
			Lock lock, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {

		this.handle = handle;
		this.errHandler = errHandler;
		this.addrMap = addrMap;
		this.lock = lock;

		treeAdapter = ProgramTreeDBAdapter.getAdapter(handle, openMode);

		initTreeMap(openMode, monitor);
	}

	@Override
	public void setProgram(ProgramDB program) {
		this.program = program;

		if (treeMap.isEmpty()) {
			createDefaultTree();
		}
	}

	@Override
	public void programReady(int openMode1, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		// Nothing to do
	}

	public void imageBaseChanged(boolean commit) {
		lock.acquire();
		try {
			Iterator<ModuleManager> iter = treeMap.values().iterator();
			while (iter.hasNext()) {
				ModuleManager m = iter.next();
				m.imageBaseChanged(commit);
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Create a new tree with given name.
	 * @param treeName name of the tree (not the root module)
	 * @return root module for the new tree
	 * @throws DuplicateNameException if there is already tree named
	 * treeName
	 */
	public ProgramModule createRootModule(String treeName) throws DuplicateNameException {

		lock.acquire();
		try {
			if (treeMap.containsKey(treeName)) {
				throw new DuplicateNameException(
					"Root module named " + treeName + " already exists");
			}
			DBRecord record = treeAdapter.createRecord(treeName);
			ModuleManager m =
				new ModuleManager(this, record, DBConstants.CREATE, TaskMonitor.DUMMY);
			treeMap.put(treeName, m);
			addMemoryBlocks(m);
			if (program != null) {
				// no notification for initial default tree
				program.programTreeAdded(record.getKey(), ChangeManager.DOCR_TREE_CREATED, null,
					treeName);
			}
			return m.getRootModule();
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		catch (VersionException | CancelledException e) {
			throw new RuntimeException(e); // unexpected exception
		}
		finally {
			lock.release();
		}
		return null;
	}

	/**
	 * Get the root module of the tree with the given name.
	 * @param treeName tree name
	 * @return root module, or null if there is no tree with the
	 * given name
	 */
	public ProgramModule getRootModule(String treeName) {
		lock.acquire();
		try {
			ModuleManager m = treeMap.get(treeName);
			if (m != null) {
				return m.getRootModule();
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;

	}

	/**
	 * Returns the root module for the default program tree. The default tree is the oldest tree.
	 * @return  the root module for the default program tree. The default tree is the oldest tree.
	 */
	public ProgramModule getDefaultRootModule() {
		try {
			RecordIterator iter = treeAdapter.getRecords();
			while (iter.hasNext()) {
				DBRecord record = iter.next();
				String name = record.getString(ProgramTreeDBAdapter.TREE_NAME_COL);
				return getRootModule(name);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return null;
	}

	/**
	 * Get the names of all the trees in the program.
	 * @return sorted array of tree names
	 */
	public String[] getTreeNames() {
		String[] names = new String[treeMap.size()];
		try {
			RecordIterator iter = treeAdapter.getRecords();

			int index = 0;
			while (iter.hasNext()) {
				DBRecord record = iter.next();
				names[index] = record.getString(ProgramTreeDBAdapter.TREE_NAME_COL);
				++index;
			}
			return names;
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return new String[0];
	}

	/**
	 * Rename the tree to the new name. This method has no effect on the
	 * name of the root module.
	 * @param oldName old name of root module
	 * @param newName new name for root module
	 * @throws DuplicateNameException if newName exists as the name
	 * for another root
	 */
	public void renameTree(String oldName, String newName) throws DuplicateNameException {
		lock.acquire();
		try {
			if (treeMap.containsKey(newName)) {
				throw new DuplicateNameException("Name " + newName + " already exists");
			}
			ModuleManager moduleMgr = treeMap.get(oldName);
			if (moduleMgr == null) {
				throw new IllegalArgumentException("Tree named " + oldName + " was not found");
			}
			moduleMgr.setName(newName);

			treeMap.remove(oldName);
			treeMap.put(newName, moduleMgr);
			program.programTreeChanged(moduleMgr.getTreeID(), ChangeManager.DOCR_TREE_RENAMED, null,
				oldName, newName);

		}
		finally {
			lock.release();
		}
	}

	/**
	 * Remove the tree with the given name.
	 * @param treeName tree name
	 * @return true if the tree was removed
	 */
	public boolean removeTree(String treeName) {
		lock.acquire();
		try {
			if (treeMap.containsKey(treeName)) {
				DBRecord rec = treeAdapter.getRecord(treeName);
				treeAdapter.deleteRecord(rec.getKey());
				ModuleManager mm = treeMap.remove(treeName);
				mm.dispose();
				program.programTreeChanged(rec.getKey(), ChangeManager.DOCR_TREE_REMOVED, null,
					treeName, null);
				return true;
			}

		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return false;
	}

	/**
	 * Get the module with the given name that is in the tree identified
	 * by the treeName.
	 * @param treeName name of the tree
	 * @param name module name to look for
	 * @return null if there is no module with the given name in the tree
	 */
	public ProgramModule getModule(String treeName, String name) {
		lock.acquire();
		try {
			ModuleManager m = treeMap.get(treeName);
			if (m != null) {
				return m.getModule(name);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);

		}
		finally {
			lock.release();
		}

		return null;
	}

	/**
	 * Get the fragment with the given name that is in the tree identified
	 * by the treeName.
	 * @param treeName name of the tree
	 * @param name name of fragment to look for
	 * @return null if there is no fragment with the given name in the tree
	 */
	public ProgramFragment getFragment(String treeName, String name) {
		lock.acquire();
		try {
			ModuleManager m = treeMap.get(treeName);
			if (m != null) {
				return m.getFragment(name);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);

		}
		finally {
			lock.release();
		}
		return null;
	}

	/**
	 * Get the fragment that contains the given address within the tree
	 * identified by the treeName.
	 * @param treeName name of the tree
	 * @param addr address contained within some fragment
	 * @return fragment containing addr, or null if addr does not
	 * exist in memory
	 */
	public ProgramFragment getFragment(String treeName, Address addr) {
		lock.acquire();
		try {
			ModuleManager m = treeMap.get(treeName);
			if (m != null) {
				return m.getFragment(addr);
			}

		}
		catch (IOException e) {
			errHandler.dbError(e);

		}
		finally {
			lock.release();
		}
		return null;
	}

	/**
	 * Add a memory block with the given range.
	 * @param name memory block name (name of new fragment)
	 * @param range memory block address range
	 */
	public void addMemoryBlock(String name, AddressRange range) {
		lock.acquire();
		try {
			Iterator<String> keys = treeMap.keySet().iterator();
			while (keys.hasNext()) {
				ModuleManager m = treeMap.get(keys.next());
				m.addMemoryBlock(name, range);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		lock.acquire();
		try {
			Iterator<String> keys = treeMap.keySet().iterator();
			while (keys.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				ModuleManager m = treeMap.get(keys.next());
				m.removeMemoryBlock(startAddr, endAddr, monitor);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);

		}
		finally {
			lock.release();
		}
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws AddressOverflowException, CancelledException {

		lock.acquire();

		try {
			Iterator<String> keys = treeMap.keySet().iterator();
			monitor.setMessage("Moving folders/fragments...");
			while (keys.hasNext()) {
				monitor.checkCancelled();
				ModuleManager m = treeMap.get(keys.next());
				m.moveAddressRange(fromAddr, toAddr, length, monitor);
				m.invalidateCache();
			}
			// rebuild the map
			treeMap.clear();
			refreshTreeMap(false);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	AddressMap getAddressMap() {
		return addrMap;
	}

	DBHandle getDatabaseHandle() {
		return handle;
	}

	String getTreeName(long treeID) {
		try {
			DBRecord record = treeAdapter.getRecord(treeID);
			if (record != null) {
				return record.getString(ProgramTreeDBAdapter.TREE_NAME_COL);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return null;
	}

	ErrorHandler getErrorHandler() {
		return errHandler;
	}

	/////////////////////////////////////////////////////////////////////
	/**
	 * Method addMemoryBlocks; called when a new module manager is
	 * being created.
	 */
	private void addMemoryBlocks(ModuleManager mgr) {
		Memory memory = program.getMemory();
		MemoryBlock[] blocks = memory.getBlocks();
		for (MemoryBlock block : blocks) {
			AddressRange range = new AddressRangeImpl(block.getStart(), block.getEnd());
			try {
				mgr.addMemoryBlock(block.getName(), range);
			}
			catch (IOException e) {
				errHandler.dbError(e);
				break;
			}
		}
	}

	/**
	 * Populate the map with existing tree views.
	 * @throws VersionException if a DB schema version differs from expected version
	 * @throws CancelledException if operation cancelled
	 */
	private void initTreeMap(int openMode, TaskMonitor monitor)
			throws IOException, CancelledException, VersionException {
		treeMap = new HashMap<>();
		RecordIterator iter = treeAdapter.getRecords();
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			String treeName = rec.getString(ProgramTreeDBAdapter.TREE_NAME_COL);
			ModuleManager mm = new ModuleManager(this, rec, openMode, monitor);
			treeMap.put(treeName, mm);
		}
	}

	/**
	 * Re-Populate the map with existing tree views following an invalidation (e.g., undo, redo, memory movement).
	 * @param ignoreModificationNumber if true all existing module managers will be invalidated, otherwise 
	 * only those module managers whose modification number does not match the corresponding tree modification
	 * number will be invalidated.
	 */
	private void refreshTreeMap(boolean ignoreModificationNumber) throws IOException {
		Map<String, ModuleManager> oldTreeMap = treeMap;
		treeMap = new HashMap<>();

		RecordIterator iter = treeAdapter.getRecords();
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			long key = rec.getKey();
			String treeName = rec.getString(ProgramTreeDBAdapter.TREE_NAME_COL);
			long modNumber = rec.getLongValue(ProgramTreeDBAdapter.MODIFICATION_NUM_COL);
			ModuleManager mm = oldTreeMap.get(treeName);
			if (mm != null) {
				oldTreeMap.remove(treeName);
				if (mm.getTreeID() == key) {
					if (ignoreModificationNumber || mm.getModificationNumber() != modNumber) {
						mm.invalidateCache();
					}
				}
				else {
					mm.invalidateCache();
					mm = null;
				}
			}
			if (mm == null) {
				try {
					mm = new ModuleManager(this, rec, DBConstants.UPDATE, TaskMonitor.DUMMY);
				}
				catch (VersionException | CancelledException e) {
					throw new RuntimeException(e); // unexpected exception
				}
			}
			treeMap.put(treeName, mm);
		}
		Iterator<String> it = oldTreeMap.keySet().iterator();
		while (it.hasNext()) {
			ModuleManager mm = oldTreeMap.get(it.next());
			mm.invalidateCache();
		}
	}

	@Override
	public void invalidateCache(boolean all) throws IOException {
		lock.acquire();
		try {
			refreshTreeMap(all);
		}
		finally {
			lock.release();
		}
	}

	public void setProgramName(String oldName, String newName) {
		Iterator<String> it = treeMap.keySet().iterator();
		while (it.hasNext()) {
			ModuleManager mm = treeMap.get(it.next());
			mm.setProgramName(oldName, newName);
		}
	}

	void updateTreeRecord(DBRecord record) {
		updateTreeRecord(record, true);
	}

	/**
	 * Update the record in the database.
	 * @param record record to update in the database
	 * @param updateModificationNumber true means to update the
	 * modification number
	 */
	void updateTreeRecord(DBRecord record, boolean updateModificationNumber) {
		try {
			if (updateModificationNumber) {
				record.setLongValue(ProgramTreeDBAdapter.MODIFICATION_NUM_COL,
					record.getLongValue(ProgramTreeDBAdapter.MODIFICATION_NUM_COL) + 1);
			}
			treeAdapter.updateRecord(record);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
	}

	DBRecord getTreeRecord(long treeID) {
		try {
			return treeAdapter.getRecord(treeID);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return null;
	}

	private void createDefaultTree() {
		try {
			createRootModule(DEFAULT_TREE_NAME);
		}
		catch (DuplicateNameException e) {
			throw new RuntimeException(e); // unexpected exception
		}
	}

	/**
	 * Get the root module for the tree that has the given ID.
	 * @param treeID ID of the tree
	 * @return root module
	 */
	public ProgramModule getRootModule(long treeID) {
		String treeName = getTreeName(treeID);
		return getRootModule(treeName);
	}

	Lock getLock() {
		return lock;
	}

	ProgramDB getProgram() {
		return program;
	}

}
