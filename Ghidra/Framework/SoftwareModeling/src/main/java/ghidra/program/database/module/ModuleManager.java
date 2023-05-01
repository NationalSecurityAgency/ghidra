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
import java.util.ArrayList;
import java.util.HashSet;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.util.AddressRangeMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ChangeManager;
import ghidra.util.Lock;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 *
 * Manages the tables for modules and fragments in a tree view.
 *
 *
 */
class ModuleManager {

	static final String FRAGMENT_ADDRESS_TABLE_NAME = "Fragment Addresses";

	private AddressMap addrMap;
	private long treeID;
	private ModuleDBAdapter moduleAdapter;
	private FragmentDBAdapter fragmentAdapter;
	private ParentChildDBAdapter parentChildAdapter;
	private DBObjectCache<ModuleDB> moduleCache;
	private DBObjectCache<FragmentDB> fragCache;
	private TreeManager treeMgr;
	private HashSet<String> nameSet;
	private AddressRangeMapDB fragMap;
	private ErrorHandler errHandler;
	private DBRecord record;
	private Object versionTag; // gets updated everytime this module manager's cache is invalidated,
	// or a new memory block is added

	private Lock lock;

	static long ROOT_MODULE_ID = 0;

	/**
	 * Construct a program tree module manager
	 * @param treeMgr program tree manager
	 * @param rec program tree record
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param monitor task monitor
	 * @throws IOException if a database IO error occurs
	 * @throws CancelledException if monitor cancelled (upgrade case only)
	 * @throws VersionException if opening an existing program tree and an underlying table 
	 * schema version differs from the expected version.
	 */
	ModuleManager(TreeManager treeMgr, DBRecord rec, int openMode, TaskMonitor monitor)
			throws IOException, CancelledException, VersionException {

		this.treeMgr = treeMgr;
		this.treeID = rec.getKey();
		this.record = rec;
		lock = treeMgr.getLock();
		versionTag = new Object();
		addrMap = treeMgr.getAddressMap();
		nameSet = new HashSet<>();
		errHandler = treeMgr.getErrorHandler();

		initializeAdapters(openMode, monitor);

		moduleCache = new DBObjectCache<>(100);
		fragCache = new DBObjectCache<>(100);

		if (openMode == DBConstants.CREATE) {
			createRootModule();
		}
	}

	static String getFragAddressTableName(long treeID) {
		return FRAGMENT_ADDRESS_TABLE_NAME + treeID;
	}

	private void initializeAdapters(int openMode, TaskMonitor monitor)
			throws CancelledException, IOException, VersionException {

		DBHandle handle = treeMgr.getDatabaseHandle();

		VersionException versionExc = null;

		try {
			parentChildAdapter = ParentChildDBAdapter.getAdapter(handle, openMode, treeID);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			// ParentChildDBAdapter must be available for upgrade use
			moduleAdapter = ModuleDBAdapter.getAdapter(this, openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			fragmentAdapter = FragmentDBAdapter.getAdapter(handle, openMode, treeID);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}

		if (addrMap.isUpgraded()) {
			if (openMode == DBConstants.UPDATE) {
				versionExc = (new VersionException(true)).combine(versionExc);
			}
			else if (openMode == DBConstants.UPGRADE) {
				addressUpgrade(handle, monitor);
			}
		}

		fragMap = new AddressRangeMapDB(handle, addrMap, lock,
			getFragAddressTableName(treeID), errHandler, LongField.INSTANCE, true);

		if (versionExc != null) {
			throw versionExc;
		}
	}

	long getTreeID() {
		return treeID;
	}

	ModuleDBAdapter getModuleAdapter() {
		return moduleAdapter;
	}

	FragmentDBAdapter getFragmentAdapter() {
		return fragmentAdapter;
	}

	ParentChildDBAdapter getParentChildAdapter() {
		return parentChildAdapter;
	}

	Lock getLock() {
		return lock;
	}

	private void addressUpgrade(DBHandle handle, TaskMonitor monitor)
			throws IOException, CancelledException {

		String mapName = getFragAddressTableName(treeID);

		AddressRangeMapDB map = new AddressRangeMapDB(handle, addrMap.getOldAddressMap(),
			treeMgr.getLock(), mapName, errHandler, LongField.INSTANCE, true);
		if (map.isEmpty()) {
			return;
		}

		String name = record.getString(ProgramTreeDBAdapter.TREE_NAME_COL);
		monitor.setMessage("Upgrading Program Tree (" + name + ")...");

		// Upgrade ranges into temporary map
		DBHandle tmpDb = new DBHandle();
		try {
			tmpDb.startTransaction();

			monitor.initialize(map.getRecordCount());
			int count = 0;

			AddressRangeMapDB tmpMap = new AddressRangeMapDB(tmpDb, addrMap,
				new Lock("Tmp Upgrade"), mapName, errHandler, LongField.INSTANCE, false);

			AddressRangeIterator iter = map.getAddressRanges();
			while (iter.hasNext()) {
				monitor.checkCancelled();
				AddressRange range = iter.next();
				Address startAddr = range.getMinAddress();
				Address endAddr = range.getMaxAddress();
				Field value = map.getValue(startAddr);

				tmpMap.paintRange(startAddr, endAddr, value);

				monitor.setProgress(++count);
			}

			monitor.initialize(count);
			count = 0;

			map.dispose(); // deletes old map table

			// Copy ranges into new map
			map = new AddressRangeMapDB(handle, addrMap, treeMgr.getLock(), mapName, errHandler,
				LongField.INSTANCE, true);
			iter = tmpMap.getAddressRanges();
			while (iter.hasNext()) {
				monitor.checkCancelled();
				AddressRange range = iter.next();
				map.paintRange(range.getMinAddress(), range.getMaxAddress(),
					tmpMap.getValue(range.getMinAddress()));
				monitor.setProgress(++count);
			}

			tmpMap.dispose();
		}
		finally {
			tmpDb.close();
		}
	}

	void setName(String name) {
		lock.acquire();
		try {
			record.setString(ProgramTreeDBAdapter.TREE_NAME_COL, name);
			treeMgr.updateTreeRecord(record, false);
		}
		finally {
			lock.release();
		}
	}

	void imageBaseChanged(boolean commit) {
		lock.acquire();
		try {
			if (commit) {
				treeMgr.updateTreeRecord(record, true);
			}
			invalidateCache();
		}
		finally {
			lock.release();
		}
	}

	/**
	 *
	 */
	private void createRootModule() throws IOException {
		DBRecord rootRecord = moduleAdapter.createModuleRecord(0, getProgram().getName());
		ModuleDB root = new ModuleDB(this, moduleCache, rootRecord);
		nameSet.add(root.getName());
	}

	void dbError(IOException e) {
		errHandler.dbError(e);
	}

	void setProgramName(String oldName, String newName) {
		lock.acquire();
		try {
			ModuleDB root = getModuleDB(ROOT_MODULE_ID);
			DBRecord rec = root.getRecord();
			rec.setString(ModuleDBAdapter.MODULE_NAME_COL, newName);
			moduleAdapter.updateModuleRecord(rec);
			treeMgr.updateTreeRecord(record);
			nameChanged(oldName, root);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	ProgramModule getRootModule() throws IOException {
		return getModuleDB(0);
	}

	ProgramModule getModule(String name) throws IOException {
		DBRecord moduleRecord = moduleAdapter.getModuleRecord(name);
		return getModuleDB(moduleRecord);
	}

	ProgramFragment getFragment(String name) throws IOException {
		DBRecord fragmentRecord = fragmentAdapter.getFragmentRecord(name);
		return getFragmentDB(fragmentRecord);
	}

	ProgramFragment getFragment(Address addr) throws IOException {
		Field field = fragMap.getValue(addr);
		if (field != null) {
			return getFragmentDB(field.getLongValue());
		}
		return null;
	}

	void addMemoryBlock(String name, AddressRange range) throws IOException {
		lock.acquire();

		try {
			FragmentDB frag = (FragmentDB) getFragment(name);
			if (frag == null) {
				frag = createFragmentAdjustNameAsNeeded(name);
			}
			frag.addRange(range);
			fragMap.paintRange(range.getMinAddress(), range.getMaxAddress(),
				new LongField(frag.getKey()));
			treeMgr.updateTreeRecord(record);
			versionTag = new Object(); //update the version tag
		}
		finally {
			lock.release();
		}
	}

	private FragmentDB createFragmentAdjustNameAsNeeded(String baseName) throws IOException {
		ProgramModule root = getRootModule();
		String newFragmentName = baseName;
		long counter = 0;

		while (true) {
			try {
				return (FragmentDB) root.createFragment(newFragmentName);
			}
			catch (DuplicateNameException e) {
				counter++;
				newFragmentName = baseName + "." + counter;
			}
		}
	}

	void removeMemoryBlock(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws IOException {

		lock.acquire();
		try {
			AddressRangeIterator iter = fragMap.getAddressRanges(startAddr, endAddr);
			while (iter.hasNext() && !monitor.isCancelled()) {
				AddressRange range = iter.next();
				Field field = fragMap.getValue(range.getMinAddress());
				FragmentDB frag = getFragmentDB(field.getLongValue());
				frag.removeRange(
					new AddressRangeImpl(range.getMinAddress(), range.getMaxAddress()));
				if (frag.isEmpty()) {
					removeFragment(frag);
				}
			}
			if (monitor.isCancelled()) {
				return;
			}
			fragMap.clearRange(startAddr, endAddr);
			treeMgr.updateTreeRecord(record);
			invalidateCache();

		}
		finally {
			lock.release();
		}

	}

	void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws AddressOverflowException, CancelledException {

		lock.acquire();
		try {
			Address rangeEnd = fromAddr.addNoWrap(length - 1);

			AddressSet addrSet = new AddressSet(fromAddr, rangeEnd);
			ArrayList<FragmentHolder> list = new ArrayList<>();

			AddressRangeIterator rangeIter = fragMap.getAddressRanges(fromAddr, rangeEnd);
			while (rangeIter.hasNext() && !addrSet.isEmpty()) {
				monitor.checkCancelled();
				AddressRange range = rangeIter.next();
				Field field = fragMap.getValue(range.getMinAddress());
				try {
					FragmentDB frag = getFragmentDB(field.getLongValue());
					AddressSet intersection = addrSet.intersect(frag);
					AddressRangeIterator fragRangeIter = intersection.getAddressRanges();
					while (fragRangeIter.hasNext() && !monitor.isCancelled()) {
						AddressRange fragRange = fragRangeIter.next();

						Address startAddr = fragRange.getMinAddress();
						Address endAddr = fragRange.getMaxAddress();

						long offset = startAddr.subtract(fromAddr);
						startAddr = toAddr.add(offset);
						offset = endAddr.subtract(fromAddr);
						endAddr = toAddr.add(offset);

						AddressRange newRange = new AddressRangeImpl(startAddr, endAddr);

						frag.removeRange(fragRange);
						list.add(new FragmentHolder(frag, newRange));
					}
					addrSet = addrSet.subtract(intersection);
				}
				catch (IOException e) {
					errHandler.dbError(e);
					return;
				}

			}

			monitor.checkCancelled();
			fragMap.clearRange(fromAddr, rangeEnd);

			for (int i = 0; i < list.size(); i++) {
				monitor.checkCancelled();
				FragmentHolder fh = list.get(i);
				fragMap.paintRange(fh.range.getMinAddress(), fh.range.getMaxAddress(),
					new LongField(fh.frag.getKey()));
				fh.frag.addRange(fh.range);
			}
			treeMgr.updateTreeRecord(record);

			// generate an event...
			getProgram().programTreeChanged(treeID, ChangeManager.DOCR_FRAGMENT_MOVED, null,
				new AddressRangeImpl(fromAddr, rangeEnd),
				new AddressRangeImpl(toAddr, toAddr.addNoWrap(length - 1)));

		}
		finally {
			lock.release();
		}
	}

	void fragmentAdded(long parentID, ProgramFragment fragment) {
		lock.acquire();
		try {
			ProgramModule parent = getModuleDB(parentID);
			nameSet.add(fragment.getName());
			treeMgr.updateTreeRecord(record);
			getProgram().programTreeChanged(treeID, ChangeManager.DOCR_GROUP_ADDED, null, parent,
				fragment);
		}
		catch (IOException e) {
			errHandler.dbError(e);

		}
		finally {
			lock.release();
		}
	}

	void moduleAdded(long parentID, ProgramModule module) {
		lock.acquire();
		try {
			ProgramModule parent = getModuleDB(parentID);
			nameSet.add(module.getName());
			treeMgr.updateTreeRecord(record);
			getProgram().programTreeChanged(treeID, ChangeManager.DOCR_GROUP_ADDED, null, parent,
				module);
		}
		catch (IOException e) {
			errHandler.dbError(e);

		}
		finally {
			lock.release();
		}
	}

	void groupRemoved(ModuleDB parentModule, long childID, String childName, boolean isFragment,
			boolean deleteChild) {
		lock.acquire();
		try {
			if (deleteChild && isFragment) {
				nameSet.remove(childName);
				fragCache.delete(childID);
			}
			else if (deleteChild) {
				nameSet.remove(childName);
				moduleCache.delete(childID);

			}
			treeMgr.updateTreeRecord(record);
			getProgram().programTreeChanged(treeID, ChangeManager.DOCR_GROUP_REMOVED, null,
				parentModule,
				childName);

		}
		finally {
			lock.release();
		}
	}

	void commentsChanged(String oldComments, Group group) {
		lock.acquire();
		try {
			treeMgr.updateTreeRecord(record);

			getProgram().programTreeChanged(treeID, ChangeManager.DOCR_GROUP_COMMENT_CHANGED, null,
				oldComments, group);

		}
		finally {
			lock.release();
		}

	}

	void nameChanged(String oldName, Group group) {
		lock.acquire();
		try {
			nameSet.remove(oldName);
			nameSet.add(group.getName());
			treeMgr.updateTreeRecord(record);
			getProgram().programTreeChanged(treeID, ChangeManager.DOCR_GROUP_RENAMED, null, oldName,
				group);

		}
		finally {
			lock.release();
		}
	}

	/**
	 * Perform recursive check to determine if specified id is a child or decendant
	 * of the specified module.
	 * @param id descendent child id (positive for module, negative for fragment)
	 * @param moduleID module id (positive)
	 * @return true if specified id is a descendant of moduleID.
	 * @throws IOException if database IO error occurs
	 */
	boolean isDescendant(long id, long moduleID) throws IOException {

		Field[] keys =
			parentChildAdapter.getParentChildKeys(moduleID, ParentChildDBAdapter.PARENT_ID_COL);
		if (keys.length == 0) {
			return false;
		}
		for (Field key : keys) {
			DBRecord parentChildRecord =
				parentChildAdapter.getParentChildRecord(key.getLongValue());
			long childID = parentChildRecord.getLongValue(ParentChildDBAdapter.CHILD_ID_COL);

			if (childID == id) {
				return true;
			}
			if (isDescendant(id, childID)) {
				return true;
			}
		}
		return false;
	}

	FragmentDB getFragmentDB(DBRecord fragmentRecord) {
		lock.acquire();
		try {
			if (fragmentRecord == null) {
				return null;
			}
			FragmentDB f = fragCache.get(fragmentRecord.getKey());
			if (f != null) {
				return f;
			}
			return createFragmentDB(fragmentRecord);

		}
		finally {
			lock.release();
		}
	}

	FragmentDB getFragmentDB(long fragID) throws IOException {
		lock.acquire();
		try {
			FragmentDB frag = fragCache.get(fragID);
			if (frag != null) {
				return frag;
			}
			DBRecord fragmentRecord = fragmentAdapter.getFragmentRecord(fragID);
			return createFragmentDB(fragmentRecord);

		}
		finally {
			lock.release();
		}
	}

	ModuleDB getModuleDB(DBRecord moduleRecord) throws IOException {
		if (moduleRecord == null) {
			return null;
		}
		ModuleDB moduleDB = moduleCache.get(moduleRecord.getKey());
		if (moduleDB != null) {
			return moduleDB;
		}
		return createModuleDB(moduleRecord);
	}

	ModuleDB getModuleDB(long moduleID) throws IOException {
		ModuleDB moduleDB = moduleCache.get(moduleID);
		if (moduleDB != null) {
			return moduleDB;
		}
		DBRecord moduleRecord = moduleAdapter.getModuleRecord(moduleID);
		return createModuleDB(moduleRecord);
	}

	String getTreeName() {
		return treeMgr.getTreeName(treeID);
	}

	CodeUnitIterator getCodeUnits(FragmentDB fragmentDB) {
		return getProgram().getListing().getCodeUnits(fragmentDB, true);
	}

	/**
	 * Move code units in the range to the destination fragment.
	 * @param destFrag destination fragment
	 * @param min min address
	 * @param max max address
	 * @throws NotFoundException if address range not fully contained within program memory 
	 */
	void move(FragmentDB destFrag, Address min, Address max) throws NotFoundException {

		lock.acquire();
		try {
			if (!getProgram().getMemory().contains(min, max)) {
				throw new NotFoundException(
					"Address range for " + min + ", " + max + " is not contained in memory");
			}
			AddressSet set = new AddressSet();

			AddressRangeIterator iter = fragMap.getAddressRanges(min, max);
			AddressSet addrSet = new AddressSet(min, max);

			while (iter.hasNext() && !addrSet.isEmpty()) {
				AddressRange range = iter.next();
				Field field = fragMap.getValue(range.getMinAddress());
				try {
					FragmentDB frag = getFragmentDB(field.getLongValue());
					if (frag != destFrag) {
						AddressSet intersection = addrSet.intersect(frag);
						AddressRangeIterator fragRangeIter = intersection.getAddressRanges();
						while (fragRangeIter.hasNext()) {
							AddressRange fragRange = fragRangeIter.next();
							set.add(fragRange);
							frag.removeRange(fragRange);
						}
						addrSet = addrSet.subtract(intersection);
					}
				}
				catch (IOException e) {
					errHandler.dbError(e);
					return;
				}
			}

			Field field = new LongField(destFrag.getKey());

			AddressRangeIterator rangeIter = set.getAddressRanges();
			while (rangeIter.hasNext()) {
				AddressRange range = rangeIter.next();
				fragMap.paintRange(range.getMinAddress(), range.getMaxAddress(), field);
				destFrag.addRange(range);
			}
			treeMgr.updateTreeRecord(record);

			getProgram().programTreeChanged(treeID, ChangeManager.DOCR_CODE_MOVED, null, min, max);

		}
		finally {
			lock.release();
		}
	}

	FragmentDB getFragment(CodeUnit cu) {
		lock.acquire();
		try {
			Field field = fragMap.getValue(cu.getMinAddress());
			if (field != null) {
				try {
					return getFragmentDB(field.getLongValue());
				}
				catch (IOException e) {
					errHandler.dbError(e);
				}
			}
		}
		finally {
			lock.release();
		}
		return null;
	}

	void childReordered(ModuleDB parentModule, Group child) {
		treeMgr.updateTreeRecord(record);
		getProgram().programTreeChanged(treeID, ChangeManager.DOCR_MODULE_REORDERED, parentModule,
			child,
			child);
	}

	void childReparented(Group group, String oldParentName, String newParentName) {
		treeMgr.updateTreeRecord(record);
		getProgram().programTreeChanged(treeID, ChangeManager.DOCR_GROUP_REPARENTED, group,
			oldParentName, newParentName);
	}

	String[] getParentNames(long childID) {
		lock.acquire();
		try {
			Field[] keys =
				parentChildAdapter.getParentChildKeys(childID, ParentChildDBAdapter.CHILD_ID_COL);
			String[] names = new String[keys.length];
			for (int i = 0; i < keys.length; i++) {
				DBRecord parentChildRecord =
					parentChildAdapter.getParentChildRecord(keys[i].getLongValue());
				DBRecord mrec = moduleAdapter.getModuleRecord(
					parentChildRecord.getLongValue(ParentChildDBAdapter.PARENT_ID_COL));
				names[i] = mrec.getString(ModuleDBAdapter.MODULE_NAME_COL);
			}
			return names;
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}

		return new String[0];
	}

	ProgramModule[] getParents(long childID) {
		lock.acquire();
		try {
			Field[] keys =
				parentChildAdapter.getParentChildKeys(childID, ParentChildDBAdapter.CHILD_ID_COL);
			ProgramModule[] modules = new ProgramModule[keys.length];
			for (int i = 0; i < keys.length; i++) {
				DBRecord parentChildRecord =
					parentChildAdapter.getParentChildRecord(keys[i].getLongValue());
				DBRecord mrec = moduleAdapter.getModuleRecord(
					parentChildRecord.getLongValue(ParentChildDBAdapter.PARENT_ID_COL));
				modules[i] = getModuleDB(mrec);
			}
			return modules;
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return new ProgramModule[0];
	}

	private ModuleDB createModuleDB(DBRecord moduleRecord) throws IOException {
		if (moduleRecord != null) {
			ModuleDB moduleDB;
			moduleDB = new ModuleDB(this, moduleCache, moduleRecord);
			nameSet.add(moduleDB.getName());
			return moduleDB;
		}
		return null;
	}

	private FragmentDB createFragmentDB(DBRecord fragmentRecord) {
		if (fragmentRecord != null) {
			FragmentDB f = new FragmentDB(this, fragCache, fragmentRecord,
				getFragmentAddressSet(fragmentRecord.getKey()));
			nameSet.add(f.getName());
			return f;
		}
		return null;
	}

	private void removeFragment(FragmentDB frag) {
		// remove frag from all of its parents
		ProgramModule[] parents = frag.getParents();
		for (ProgramModule parent : parents) {
			try {
				parent.removeChild(frag.getName());
			}
			catch (NotEmptyException e) {
				throw new AssertException("Should have removed " + frag.getName());
			}
		}
		fragCache.delete(frag.getKey());
	}

	AddressSet getFragmentAddressSet(long fragID) {
		return fragMap.getAddressSet(new LongField(fragID));
	}

	private class FragmentHolder {
		FragmentDB frag;
		AddressRange range;

		FragmentHolder(FragmentDB frag, AddressRange range) {
			this.frag = frag;
			this.range = range;
		}
	}

	void invalidateCache() {
		lock.acquire();
		try {
			versionTag = new Object();
			moduleCache.invalidate();
			fragCache.invalidate();
			record = treeMgr.getTreeRecord(treeID);
		}
		finally {
			lock.release();
		}

	}

	Object getVersionTag() {
		return versionTag;
	}

	long getModificationNumber() {
		return record.getLongValue(ProgramTreeDBAdapter.MODIFICATION_NUM_COL);
	}

	void dispose() throws IOException {
		fragMap.dispose();
		DBHandle handle = treeMgr.getDatabaseHandle();
		handle.deleteTable(ParentChildDBAdapter.getTableName(treeID));
		handle.deleteTable(ModuleDBAdapter.getTableName(treeID));
		handle.deleteTable(FragmentDBAdapter.getTableName(treeID));
	}

	ProgramDB getProgram() {
		return treeMgr.getProgram();
	}

	DBHandle getDatabaseHandle() {
		return treeMgr.getDatabaseHandle();
	}
}
