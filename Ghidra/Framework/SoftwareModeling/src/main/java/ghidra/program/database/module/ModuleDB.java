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

import db.DBRecord;
import db.Field;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.Lock;
import ghidra.util.exception.*;

/**
 *
 * Database implementation for Module.
 *  
 * 
 */
class ModuleDB extends DatabaseObject implements ProgramModule {

	private DBRecord record;
	private ModuleManager moduleMgr;
	private ModuleDBAdapter moduleAdapter;
	private FragmentDBAdapter fragmentAdapter;
	private ParentChildDBAdapter parentChildAdapter;

	private int childCount; // cache the count so we don't have to access 
							// database records
	private Lock lock;

	/**
	 * 
	 * Constructor
	 * @param moduleMgr module manager
	 * @param cache ModuleDB cache
	 * @param record database record for this module
	 * @throws IOException if database IO error occurs
	 */
	ModuleDB(ModuleManager moduleMgr, DBObjectCache<ModuleDB> cache, DBRecord record)
			throws IOException {
		super(cache, record.getKey());
		this.moduleMgr = moduleMgr;
		this.record = record;
		childCount = record.getIntValue(ModuleDBAdapter.MODULE_CHILD_COUNT_COL);
		moduleAdapter = moduleMgr.getModuleAdapter();
		fragmentAdapter = moduleMgr.getFragmentAdapter();
		parentChildAdapter = moduleMgr.getParentChildAdapter();
		lock = moduleMgr.getLock();
	}

	@Override
	protected boolean refresh() {
		try {
			DBRecord rec = moduleAdapter.getModuleRecord(key);
			if (rec != null) {
				record = rec;
				childCount = rec.getIntValue(ModuleDBAdapter.MODULE_CHILD_COUNT_COL);
				return true;
			}
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		return false;
	}

	@Override
	public void add(ProgramFragment fragment) throws DuplicateGroupException {
		lock.acquire();
		try {
			checkDeleted();
			FragmentDB frag = (FragmentDB) fragment;
			long fragID = frag.getKey();
			// add a row to the parent/child table
			DBRecord parentChildRecord = parentChildAdapter.getParentChildRecord(key, -fragID);
			if (parentChildRecord != null) {
				throw new DuplicateGroupException(
					frag.getName() + " already exists a child of " + getName());
			}

			DBRecord pcRec = parentChildAdapter.addParentChildRecord(key, -fragID);
			updateChildCount(1);
			updateOrderField(pcRec, childCount - 1);
			moduleMgr.fragmentAdded(key, frag);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void add(ProgramModule module)
			throws CircularDependencyException, DuplicateGroupException {

		lock.acquire();
		try {
			checkDeleted();
			ModuleDB moduleDB = (ModuleDB) module;
			long moduleID = moduleDB.getKey();

			DBRecord parentChildRecord = parentChildAdapter.getParentChildRecord(key, moduleID);
			if (parentChildRecord != null) {
				throw new DuplicateGroupException(
					module.getName() + " already exists a child of " + getName());
			}
			if (moduleMgr.isDescendant(key, moduleID)) {
				throw new CircularDependencyException(
					getName() + " is already a descendant of " + module.getName());
			}

			DBRecord pcRec = parentChildAdapter.addParentChildRecord(key, moduleID);
			updateChildCount(1);
			updateOrderField(pcRec, childCount - 1);
			moduleMgr.moduleAdded(key, module);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean contains(ProgramFragment fragment) {
		if (!(fragment instanceof FragmentDB)) {
			return false;
		}
		FragmentDB frag = (FragmentDB) fragment;
		if (moduleMgr != frag.getModuleManager()) {
			return false;
		}
		return contains(-frag.getKey());
	}

	@Override
	public boolean contains(ProgramModule module) {
		if (!(module instanceof ModuleDB)) {
			return false;
		}
		ModuleDB moduleDB = (ModuleDB) module;
		if (moduleMgr != moduleDB.moduleMgr) {
			return false;
		}
		return contains(moduleDB.getKey());
	}

	@Override
	public ProgramFragment createFragment(String fragmentName) throws DuplicateNameException {

		lock.acquire();
		try {
			checkDeleted();
			if (moduleAdapter.getModuleRecord(fragmentName) != null ||
				fragmentAdapter.getFragmentRecord(fragmentName) != null) {
				throw new DuplicateNameException(fragmentName + " already exists");
			}
			DBRecord fragmentRecord = fragmentAdapter.createFragmentRecord(key, fragmentName);
			DBRecord pcRec = parentChildAdapter.addParentChildRecord(key, -fragmentRecord.getKey()); // negative value to indicates fragment
			updateChildCount(1);
			updateOrderField(pcRec, childCount - 1);

			FragmentDB frag = moduleMgr.getFragmentDB(fragmentRecord);
			moduleMgr.fragmentAdded(key, frag);
			return frag;
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public ProgramModule createModule(String moduleName) throws DuplicateNameException {

		lock.acquire();
		try {
			checkDeleted();
			if (moduleAdapter.getModuleRecord(moduleName) != null ||
				fragmentAdapter.getFragmentRecord(moduleName) != null) {
				throw new DuplicateNameException(moduleName + " already exists");
			}

			DBRecord moduleRecord = moduleAdapter.createModuleRecord(key, moduleName);
			DBRecord pcRec = parentChildAdapter.addParentChildRecord(key, moduleRecord.getKey());

			ModuleDB moduleDB = moduleMgr.getModuleDB(moduleRecord);
			updateChildCount(1);
			updateOrderField(pcRec, childCount - 1);
			moduleMgr.moduleAdded(key, moduleDB);
			return moduleDB;
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public Group[] getChildren() {
		lock.acquire();
		try {
			checkIsValid();
			List<DBRecord> list = getParentChildRecords();
			Group[] kids = new Group[list.size()];
			if (kids.length != childCount) {
				// data inconsistency
				throw new IOException("Inconsistent module child count (" + kids.length + " vs. " +
					childCount + "): " + getName());
			}
			for (int i = 0; i < list.size(); i++) {
				DBRecord rec = list.get(i);
				long childID = rec.getLongValue(ParentChildDBAdapter.CHILD_ID_COL);
				if (childID < 0) {
					kids[i] = moduleMgr.getFragmentDB(-childID);
				}
				else {
					kids[i] = moduleMgr.getModuleDB(childID);
				}
			}
			return kids;
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return new Group[0];
	}

	@Override
	public String getComment() {
		lock.acquire();
		try {
			checkIsValid();
			return record.getString(ModuleDBAdapter.MODULE_COMMENTS_COL);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Address getFirstAddress() {
		lock.acquire();
		try {
			checkIsValid();
			return findFirstAddress(this);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public int getIndex(String name) {
		lock.acquire();
		try {
			checkIsValid();
			DBRecord fragmentRecord = fragmentAdapter.getFragmentRecord(name);
			DBRecord pcRec = null;
			if (fragmentRecord != null) {
				pcRec = parentChildAdapter.getParentChildRecord(key, -fragmentRecord.getKey());
			}
			else {
				DBRecord moduleRecord = moduleAdapter.getModuleRecord(name);
				if (moduleRecord != null) {
					pcRec = parentChildAdapter.getParentChildRecord(key, moduleRecord.getKey());
				}
			}
			if (pcRec != null) {
				return pcRec.getIntValue(ParentChildDBAdapter.ORDER_COL);
			}
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return -1;
	}

	@Override
	public Address getLastAddress() {
		lock.acquire();
		try {
			checkIsValid();
			return findLastAddress(this);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public Address getMaxAddress() {
		lock.acquire();
		try {
			checkIsValid();
			return findMaxAddress(this, null);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public Address getMinAddress() {
		lock.acquire();
		try {
			checkIsValid();
			return findMinAddress(this, null);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public AddressSetView getAddressSet() {
		AddressSet set = new AddressSet();
		Group[] children = getChildren();
		for (int i = 0; i < children.length; i++) {
			if (children[i] instanceof ProgramFragment) {
				set.add((ProgramFragment) children[i]);
			}
			else {
				ProgramModule m = (ProgramModule) children[i];
				set.add(m.getAddressSet());
			}
		}
		return set;
	}

	@Override
	public int getNumChildren() {
		lock.acquire();
		try {
			checkIsValid();
			return childCount;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isDescendant(ProgramFragment fragment) {
		if (!(fragment instanceof FragmentDB)) {
			return false;
		}
		lock.acquire();
		try {
			checkIsValid();
			FragmentDB frag = (FragmentDB) fragment;
			return moduleMgr.isDescendant(-frag.getKey(), key);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return false;
	}

	@Override
	public boolean isDescendant(ProgramModule module) {
		if (!(module instanceof ModuleDB)) {
			return false;
		}
		ModuleDB moduleDB = (ModuleDB) module;
		try {
			return moduleMgr.isDescendant(moduleDB.key, key);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		return false;
	}

	@Override
	public void moveChild(String name, int index) throws NotFoundException {
		lock.acquire();
		try {
			checkDeleted();
			int currentIndex = 0;
			boolean foundName = false;
			Group group = null;

			// TODO: this could be slow and may need monitor
			List<DBRecord> list = getParentChildRecords();
			for (int i = 0; i < list.size(); i++) {
				DBRecord rec = list.get(i);
				long childID = rec.getLongValue(ParentChildDBAdapter.CHILD_ID_COL);
				String childName = null;
				DBRecord childRec = null;
				if (childID < 0) {
					childRec = fragmentAdapter.getFragmentRecord(-childID);
					childName = childRec.getString(FragmentDBAdapter.FRAGMENT_NAME_COL);
				}
				else {
					childRec = moduleAdapter.getModuleRecord(childID);
					childName = childRec.getString(ModuleDBAdapter.MODULE_NAME_COL);
				}
				if (childName.equals(name)) {
					foundName = true;
					currentIndex = i;
					if (childID < 0) {
						group = moduleMgr.getFragmentDB(childRec);
					}
					else {
						group = moduleMgr.getModuleDB(childRec);
					}
				}
			}
			if (!foundName) {
				throw new NotFoundException(name + " is not a child of " + getName());
			}
			DBRecord pcRec = list.remove(currentIndex);
			list.add(index, pcRec);
			updateChildOrder(list);

			moduleMgr.childReordered(this, group);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean removeChild(String name) throws NotEmptyException {

		lock.acquire();
		try {
			checkDeleted();
			DBRecord rec = fragmentAdapter.getFragmentRecord(name);
			boolean deleteChild = false;

			if (rec != null) {
				// make sure that I am a parent of this child
				long childID = rec.getKey();
				DBRecord pcRec = parentChildAdapter.getParentChildRecord(key, -childID);
				if (pcRec == null) {
					// check for module record
					return removeModuleRecord(name);
				}
				Field[] keys = parentChildAdapter.getParentChildKeys(-childID,
					ParentChildDBAdapter.CHILD_ID_COL);
				if (keys.length == 1) {
					FragmentDB frag = moduleMgr.getFragmentDB(childID);
					if (!frag.isEmpty()) {
						throw new NotEmptyException(frag.getName() + " is not empty");
					}
					deleteChild = true;
				}
				return removeChild(childID, pcRec, true, deleteChild);
			}
			return removeModuleRecord(name);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return false;
	}

	private boolean removeModuleRecord(String name) throws IOException, NotEmptyException {

		DBRecord rec = moduleAdapter.getModuleRecord(name);
		if (rec == null) {
			return false;
		}
		boolean deleteChild = false;
		long childID = rec.getKey();
		DBRecord pcRec = parentChildAdapter.getParentChildRecord(key, childID);
		if (pcRec == null) {
			return false;
		}

		Field[] keys =
			parentChildAdapter.getParentChildKeys(childID, ParentChildDBAdapter.CHILD_ID_COL);
		if (keys.length == 1) {
			ProgramModule module = moduleMgr.getModuleDB(childID);
			if (module.getNumChildren() > 0) {
				throw new NotEmptyException(getName() + " is not empty");
			}
			deleteChild = true;
		}

		return removeChild(childID, pcRec, false, deleteChild);
	}

	@Override
	public void reparent(String name, ProgramModule oldParent) throws NotFoundException {

		Group group = null;
		ProgramFragment f = null;

		lock.acquire();
		try {
			checkDeleted();
			long childID;
			ProgramModule m = moduleMgr.getModule(name);
			if (m == null) {
				f = moduleMgr.getFragment(name);
				if (f == null) {
					throw new NotFoundException(name + " was not found as child of " + getName());
				}
				childID = -((FragmentDB) f).getKey();
				group = f;
			}
			else {
				childID = ((ModuleDB) m).key;
				group = m;
			}
			ModuleDB oldModuleDB = (ModuleDB) oldParent;

			DBRecord oldPcRec = parentChildAdapter.getParentChildRecord(oldModuleDB.key, childID);
			parentChildAdapter.removeParentChildRecord(oldPcRec.getKey());
			oldModuleDB.updateChildCount(-1);

			DBRecord newPcRec = parentChildAdapter.addParentChildRecord(key, childID);
			updateChildCount(1);
			updateOrderField(newPcRec, childCount - 1);

			oldModuleDB.resetChildOrder();

			moduleMgr.childReparented(group, oldParent.getName(), getName());
		}
		catch (IOException e) {
			moduleMgr.dbError(e);

		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean contains(CodeUnit codeUnit) {
		FragmentDB frag = moduleMgr.getFragment(codeUnit);
		if (frag != null) {
			return contains(frag);
		}
		return false;
	}

	@Override
	public String getName() {
		lock.acquire();
		try {
			checkIsValid();
			return record.getString(ModuleDBAdapter.MODULE_NAME_COL);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public int getNumParents() {
		lock.acquire();
		try {
			checkIsValid();
			Field[] keys =
				parentChildAdapter.getParentChildKeys(key, ParentChildDBAdapter.CHILD_ID_COL);
			return keys.length;
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return 0;
	}

	@Override
	public String[] getParentNames() {
		return moduleMgr.getParentNames(key);
	}

	@Override
	public ProgramModule[] getParents() {
		return moduleMgr.getParents(key);
	}

	@Override
	public String getTreeName() {
		return moduleMgr.getTreeName();
	}

	@Override
	public void setComment(String comment) {
		lock.acquire();
		try {
			checkDeleted();
			String oldComments = record.getString(ModuleDBAdapter.MODULE_COMMENTS_COL);
			if (oldComments == null || !oldComments.equals(comment)) {
				record.setString(ModuleDBAdapter.MODULE_COMMENTS_COL, comment);
				try {
					moduleAdapter.updateModuleRecord(record);
					moduleMgr.commentsChanged(oldComments, this);
				}
				catch (IOException e) {
					moduleMgr.dbError(e);
				}
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setName(String name) throws DuplicateNameException {
		lock.acquire();
		try {
			checkDeleted();
			if (key == ModuleManager.ROOT_MODULE_ID) {
				moduleMgr.getProgram().setName(name);
				return;
			}
			DBRecord r = moduleAdapter.getModuleRecord(name);
			if (r != null) {
				if (key != r.getKey()) {
					throw new DuplicateNameException(name + " already exists");
				}
				return; // no changes
			}
			if (fragmentAdapter.getFragmentRecord(name) != null) {
				throw new DuplicateNameException(name + " already exists");
			}
			String oldName = record.getString(ModuleDBAdapter.MODULE_NAME_COL);
			record.setString(ModuleDBAdapter.MODULE_NAME_COL, name);
			moduleAdapter.updateModuleRecord(record);
			moduleMgr.nameChanged(oldName, this);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	////////////////////////////////////////////////////////////	

	DBRecord getRecord() {
		return record;
	}

	private boolean contains(long childID) {
		try {
			DBRecord rec = parentChildAdapter.getParentChildRecord(key, childID);
			return rec != null;
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		return false;
	}

	private boolean removeChild(long childID, DBRecord pcRec, boolean isFragment,
			boolean deleteChild)
			throws IOException {

		parentChildAdapter.removeParentChildRecord(pcRec.getKey());
		updateChildCount(-1);

		String name = null;
		boolean success = true;
		if (isFragment) {
			DBRecord fragRec = fragmentAdapter.getFragmentRecord(childID);
			name = fragRec.getString(FragmentDBAdapter.FRAGMENT_NAME_COL);
			if (deleteChild) {
				success = fragmentAdapter.removeFragmentRecord(childID);
			}
		}
		else {
			DBRecord mrec = moduleAdapter.getModuleRecord(childID);
			name = mrec.getString(ModuleDBAdapter.MODULE_NAME_COL);
			if (deleteChild) {
				success = moduleAdapter.removeModuleRecord(childID);
			}
		}
		if (success) {
			resetChildOrder();

			moduleMgr.groupRemoved(this, childID, name, isFragment, deleteChild);
		}
		return success;
	}

	/**
	 * Get sorted list based on child order column.
	 */
	private List<DBRecord> getParentChildRecords() throws IOException {
		Field[] keys =
			parentChildAdapter.getParentChildKeys(key, ParentChildDBAdapter.PARENT_ID_COL);
		List<DBRecord> list = new ArrayList<DBRecord>();
		Comparator<DBRecord> c = new ParentChildRecordComparator();
		for (int i = 0; i < keys.length; i++) {
			DBRecord rec = parentChildAdapter.getParentChildRecord(keys[i].getLongValue());
			int index = Collections.binarySearch(list, rec, c);
			if (index < 0) {
				index = -index - 1;
			}
			list.add(index, rec);
		}
		return list;
	}

	/**
	 * Use the given list to get the child order and update each record.
	 */
	private void updateChildOrder(List<DBRecord> list) throws IOException {
		for (int i = 0; i < list.size(); i++) {
			DBRecord pcRec = list.get(i);
			if (i != pcRec.getIntValue(ParentChildDBAdapter.ORDER_COL)) {
				pcRec.setIntValue(ParentChildDBAdapter.ORDER_COL, i);
				parentChildAdapter.updateParentChildRecord(pcRec);
			}
		}
	}

	private void resetChildOrder() throws IOException {
		List<DBRecord> list = getParentChildRecords();
		updateChildOrder(list);
	}

	private void updateOrderField(DBRecord pcRec, int orderValue) throws IOException {
		pcRec.setIntValue(ParentChildDBAdapter.ORDER_COL, orderValue);
		parentChildAdapter.updateParentChildRecord(pcRec);
	}

	private Address findFirstAddress(ModuleDB module) throws IOException {
		List<DBRecord> list = module.getParentChildRecords();
		for (int i = 0; i < list.size(); i++) {
			DBRecord rec = list.get(i);
			long childID = rec.getLongValue(ParentChildDBAdapter.CHILD_ID_COL);
			if (childID < 0) {
				FragmentDB frag = moduleMgr.getFragmentDB(-childID);
				if (!frag.isEmpty()) {
					return frag.getMinAddress();
				}
			}
			else {
				ModuleDB m = moduleMgr.getModuleDB(childID);
				Address addr = findFirstAddress(m);
				if (addr != null) {
					return addr;
				}
			}
		}
		return null;
	}

	private Address findLastAddress(ModuleDB module) throws IOException {
		List<DBRecord> list = module.getParentChildRecords();
		for (int i = list.size() - 1; i >= 0; i--) {
			DBRecord rec = list.get(i);
			long childID = rec.getLongValue(ParentChildDBAdapter.CHILD_ID_COL);
			if (childID < 0) {
				FragmentDB frag = moduleMgr.getFragmentDB(-childID);
				if (!frag.isEmpty()) {
					return frag.getMaxAddress();
				}
			}
			else {
				ModuleDB m = moduleMgr.getModuleDB(childID);
				Address addr = findLastAddress(m);
				if (addr != null) {
					return addr;
				}
			}
		}
		return null;
	}

	private Address findMinAddress(ModuleDB module, Address addr) throws IOException {
		Address minAddr = addr;
		List<DBRecord> list = module.getParentChildRecords();
		for (int i = 0; i < list.size(); i++) {
			DBRecord rec = list.get(i);
			long childID = rec.getLongValue(ParentChildDBAdapter.CHILD_ID_COL);
			Address childMinAddr = null;
			if (childID < 0) {
				FragmentDB frag = moduleMgr.getFragmentDB(-childID);
				if (!frag.isEmpty()) {
					childMinAddr = frag.getMinAddress();
				}
			}
			else {
				ModuleDB m = moduleMgr.getModuleDB(childID);
				childMinAddr = findMinAddress(m, addr);
			}
			if (childMinAddr != null && minAddr == null) {
				minAddr = childMinAddr;
			}
			else if (childMinAddr != null && childMinAddr.compareTo(minAddr) < 0) {
				minAddr = childMinAddr;
			}
		}
		return minAddr;
	}

	private Address findMaxAddress(ModuleDB module, Address addr) throws IOException {
		Address maxAddr = addr;
		List<DBRecord> list = module.getParentChildRecords();
		for (int i = 0; i < list.size(); i++) {
			DBRecord rec = list.get(i);
			long childID = rec.getLongValue(ParentChildDBAdapter.CHILD_ID_COL);
			Address childMaxAddr = null;
			if (childID < 0) {
				FragmentDB frag = moduleMgr.getFragmentDB(-childID);
				if (!frag.isEmpty()) {
					childMaxAddr = frag.getMaxAddress();
				}
			}
			else {
				ModuleDB m = moduleMgr.getModuleDB(childID);
				childMaxAddr = findMaxAddress(m, addr);
			}
			if (childMaxAddr != null && maxAddr == null) {
				maxAddr = childMaxAddr;
			}
			else if (childMaxAddr != null && childMaxAddr.compareTo(maxAddr) > 0) {
				maxAddr = childMaxAddr;
			}
		}
		return maxAddr;
	}

	private void updateChildCount(int change) throws IOException {
		childCount += change;
		record.setIntValue(ModuleDBAdapter.MODULE_CHILD_COUNT_COL, childCount);
		moduleAdapter.updateModuleRecord(record);
	}

	private class ParentChildRecordComparator implements Comparator<DBRecord> {
		@Override
		public int compare(DBRecord r1, DBRecord r2) {
			int index1 = r1.getIntValue(ParentChildDBAdapter.ORDER_COL);
			int index2 = r2.getIntValue(ParentChildDBAdapter.ORDER_COL);
			if (index1 < index2) {
				return -1;
			}
			if (index1 > index2) {
				return 1;
			}
			return 0;
		}
	}

	@Override
	public Object getVersionTag() {
		return moduleMgr.getVersionTag();
	}

	@Override
	public long getModificationNumber() {
		return moduleMgr.getModificationNumber();
	}

	@Override
	public long getTreeID() {
		return moduleMgr.getTreeID();
	}

	@Override
	public String toString() {
		return record.getString(ModuleDBAdapter.MODULE_NAME_COL);
	}
}
