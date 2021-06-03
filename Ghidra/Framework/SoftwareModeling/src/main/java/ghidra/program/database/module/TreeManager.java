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
	private TreeDBAdapter adapter;
	private ProgramDB program;
	private DBHandle handle;
	private ErrorHandler errHandler;
	private int openMode;
	private Lock lock;

	static final String TREE_TABLE_NAME = "Trees";
	static final int TREE_NAME_COL = 0;
	static final int MODIFICATION_NUM_COL = 1;

	static final String MODULE_TABLE_NAME = "Module Table";
	static final int MODULE_NAME_COL = 0;
	static final int MODULE_COMMENTS_COL = 1;

	static final String FRAGMENT_TABLE_NAME = "Fragment Table";
	static final int FRAGMENT_NAME_COL = 0;
	static final int FRAGMENT_COMMENTS_COL = 1;

	static final String PARENT_CHILD_TABLE_NAME = "Parent/Child Relationships";
	static final int PARENT_ID_COL = 0;
	static final int CHILD_ID_COL = 1;
	static final int ORDER_COL = 2;

	static final String FRAGMENT_ADDRESS_TABLE_NAME = "Fragment Addresses";

	static final Schema TREE_SCHEMA = createTreeSchema();
	static final Schema MODULE_SCHEMA = createModuleSchema();
	static final Schema FRAGMENT_SCHEMA = createFragmentSchema();
	static final Schema PARENT_CHILD_SCHEMA = createParentChildSchema();

	private static Schema createTreeSchema() {
		return new Schema(0, "Key", new Field[] { StringField.INSTANCE, LongField.INSTANCE },
			new String[] { "Name", "Modification Number" });
	}

	private static Schema createModuleSchema() {
		return new Schema(0, "Key", new Field[] { StringField.INSTANCE, StringField.INSTANCE },
			new String[] { "Name", "Comments" });
	}

	private static Schema createFragmentSchema() {
		return new Schema(0, "Key", new Field[] { StringField.INSTANCE, StringField.INSTANCE },
			new String[] { "Name", "Comments" });
	}

	private static Schema createParentChildSchema() {
		return new Schema(0, "Key",
			new Field[] { LongField.INSTANCE, LongField.INSTANCE, IntField.INSTANCE },
			new String[] { "Parent ID", "Child ID", "Child Index" });
	}

	/**
	 *
	 * Construct a new TreeManager.
	 *
	 * @param handle
	 *            database handle
	 * @param errHandler
	 *            error handler
	 * @param addrMap
	 *            map to convert addresses to longs and longs to addresses
	 * @param openMode
	 *            the open mode for the program.
	 * @param lock
	 *            the program synchronization lock
	 * @param monitor
	 *            Task monitor for upgrading
	 * @throws IOException
	 *             if a database io error occurs.
	 * @throws VersionException
	 *             if the database version is different from the expected version
	 */
	public TreeManager(DBHandle handle, ErrorHandler errHandler, AddressMap addrMap, int openMode,
			Lock lock, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {

		this.handle = handle;
		this.errHandler = errHandler;
		this.addrMap = addrMap;
		this.openMode = openMode;
		this.lock = lock;
		if (openMode == DBConstants.CREATE) {
			createDBTables(handle);
		}
		findAdapters(handle);
		treeMap = new HashMap<>();

		if (addrMap.isUpgraded()) {
			if (openMode == DBConstants.UPDATE) {
				throw new VersionException(true);
			}
			if (openMode == DBConstants.UPGRADE) {
				addressUpgrade(monitor);
			}
		}
	}

	/**
	 * Set the program.
	 */
	@Override
	public void setProgram(ProgramDB program) {
		this.program = program;
		try {
			populateTreeMap(false);
			if (openMode == DBConstants.CREATE) {
				createDefaultTree();
				openMode = -1; // clear openMode flag
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
	}

	/**
	 * @see ghidra.program.database.ManagerDB#programReady(int, int, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void programReady(int openMode1, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		// Nothing to do
	}

	/**
	 * Upgrade the address maps associated with each program tree.
	 * @param monitor
	 * @throws CancelledException
	 * @throws IOException
	 */
	private void addressUpgrade(TaskMonitor monitor) throws CancelledException, IOException {
		RecordIterator iter = adapter.getRecords();
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			long key = rec.getKey();
			String treeName = rec.getString(TREE_NAME_COL);
			ModuleManager.addressUpgrade(this, key, treeName, addrMap, monitor);
		}
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
			DBRecord record = adapter.createRecord(treeName);
			ModuleManager m = new ModuleManager(this, record, program, true);
			treeMap.put(treeName, m);
			addMemoryBlocks(m);
			if (openMode != DBConstants.CREATE) {
				program.programTreeAdded(record.getKey(), ChangeManager.DOCR_TREE_CREATED, null,
					treeName);
			}
			return m.getRootModule();
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
	 * Get the root module of the tree with the given name.
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
			RecordIterator iter = adapter.getRecords();
			while (iter.hasNext()) {
				DBRecord record = iter.next();
				String name = record.getString(TREE_NAME_COL);
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
			RecordIterator iter = adapter.getRecords();

			int index = 0;
			while (iter.hasNext()) {
				DBRecord record = iter.next();
				names[index] = record.getString(TREE_NAME_COL);
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
	 * @return true if the tree was removed
	 */
	public boolean removeTree(String treeName) {
		lock.acquire();
		try {
			if (treeMap.containsKey(treeName)) {
				DBRecord rec = adapter.getRecord(treeName);
				adapter.deleteRecord(rec.getKey());
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

	/**
	 * Remove a memory block with the given range
	 * @throws CancelledException
	 */
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

	/**
	 * Move a memory block to new place.
	 * @param fromAddr old place
	 * @param toAddr new place
	 * @param length the length of the address range to move
	 * @param monitor the current task monitor
	 * @throws AddressOverflowException if an address overflow occurs.
	 * @throws CancelledException if the task is cancelled.
	 */
	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws AddressOverflowException, CancelledException {

		lock.acquire();

		try {
			Iterator<String> keys = treeMap.keySet().iterator();
			monitor.setMessage("Moving folders/fragments...");
			while (keys.hasNext()) {
				monitor.checkCanceled();
				ModuleManager m = treeMap.get(keys.next());
				m.moveAddressRange(fromAddr, toAddr, length, monitor);
				m.invalidateCache();
			}
			// rebuild the map
			treeMap.clear();
			populateTreeMap(false);
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
			DBRecord record = adapter.getRecord(treeID);
			if (record != null) {
				return record.getString(TREE_NAME_COL);
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

	static String getModuleTableName(long treeID) {
		return MODULE_TABLE_NAME + treeID;
	}

	static String getFragmentTableName(long treeID) {
		return FRAGMENT_TABLE_NAME + treeID;
	}

	static String getParentChildTableName(long treeID) {
		return PARENT_CHILD_TABLE_NAME + treeID;
	}

	static String getFragAddressTableName(long treeID) {
		return FRAGMENT_ADDRESS_TABLE_NAME + treeID;
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
	 */
	private void populateTreeMap(boolean ignoreModificationNumber) throws IOException {
		Map<String, ModuleManager> oldTreeMap = treeMap;
		treeMap = new HashMap<>();

		RecordIterator iter = adapter.getRecords();
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			long key = rec.getKey();
			String treeName = rec.getString(TREE_NAME_COL);
			long modNumber = rec.getLongValue(MODIFICATION_NUM_COL);
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
				mm = new ModuleManager(this, rec, program, false);
			}
			treeMap.put(treeName, mm);
		}
		Iterator<String> it = oldTreeMap.keySet().iterator();
		while (it.hasNext()) {
			ModuleManager mm = oldTreeMap.get(it.next());
			mm.invalidateCache();
		}
	}

	private void findAdapters(DBHandle dbHandle) throws VersionException {
		adapter = new TreeDBAdapterV0(dbHandle);
	}

	private void createDBTables(DBHandle dbHandle) throws IOException {
		dbHandle.createTable(TREE_TABLE_NAME, TREE_SCHEMA, new int[] { TREE_NAME_COL });
	}

	@Override
	public void invalidateCache(boolean all) throws IOException {
		lock.acquire();
		try {
			populateTreeMap(all);
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
				record.setLongValue(MODIFICATION_NUM_COL,
					record.getLongValue(MODIFICATION_NUM_COL) + 1);
			}
			adapter.updateRecord(record);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
	}

	DBRecord getTreeRecord(long treeID) {
		try {
			return adapter.getRecord(treeID);
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

}
