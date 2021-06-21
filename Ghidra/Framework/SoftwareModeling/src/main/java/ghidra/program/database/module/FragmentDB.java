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
import java.util.Iterator;

import db.Field;
import db.DBRecord;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.Lock;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;

/**
 *
 * Database implementation for Fragment.
 *
 */
class FragmentDB extends DatabaseObject implements ProgramFragment {

	private DBRecord record;
	private ModuleManager moduleMgr;
	private GroupDBAdapter adapter;
	private AddressSetView addrSet;
	private Lock lock;

	/**
	 * Constructor
	 * @param moduleMgr
	 * @param cache
	 * @param record
	 * @param addrSet
	 */
	FragmentDB(ModuleManager moduleMgr, DBObjectCache<FragmentDB> cache, DBRecord record,
			AddressSet addrSet) {
		super(cache, record.getKey());
		this.moduleMgr = moduleMgr;
		this.record = record;
		this.addrSet = addrSet;
		adapter = moduleMgr.getGroupDBAdapter();
		lock = moduleMgr.getLock();
	}

	@Override
	protected boolean refresh() {
		try {
			DBRecord rec = adapter.getFragmentRecord(key);
			if (rec != null) {
				record = rec;
				addrSet = moduleMgr.getFragmentAddressSet(key);
				return true;
			}
		}
		catch (IOException e) {
			moduleMgr.dbError(e);

		}
		return false;
	}

	@Override
	public boolean contains(CodeUnit codeUnit) {
		return contains(codeUnit.getMinAddress());
	}

	@Override
	public CodeUnitIterator getCodeUnits() {
		checkIsValid();
		return moduleMgr.getCodeUnits(this);
	}

	@Override
	public String getComment() {
		lock.acquire();
		try {
			checkIsValid();
			return record.getString(TreeManager.FRAGMENT_COMMENTS_COL);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String getName() {
		lock.acquire();
		try {
			checkIsValid();
			return record.getString(TreeManager.FRAGMENT_NAME_COL);
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
			Field[] keys = adapter.getParentChildKeys(-key, TreeManager.CHILD_ID_COL);
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
		return moduleMgr.getParentNames(-key);
	}

	@Override
	public ProgramModule[] getParents() {
		return moduleMgr.getParents(-key);
	}

	@Override
	public void move(Address min, Address max) throws NotFoundException {
		lock.acquire();
		try {
			checkDeleted();
			moduleMgr.move(this, min, max);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setComment(String comment) {
		lock.acquire();
		try {
			checkDeleted();
			String oldComments = record.getString(TreeManager.FRAGMENT_COMMENTS_COL);
			if (oldComments == null || !oldComments.equals(comment)) {
				record.setString(TreeManager.FRAGMENT_COMMENTS_COL, comment);
				try {
					adapter.updateFragmentRecord(record);
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
			checkIsValid();
			DBRecord r = adapter.getFragmentRecord(name);
			if (r != null) {
				if (key != r.getKey()) {
					throw new DuplicateNameException(name + " already exists");
				}
				return; // no changes
			}
			if (adapter.getModuleRecord(name) != null) {
				throw new DuplicateNameException(name + " already exists");
			}
			String oldName = record.getString(TreeManager.FRAGMENT_NAME_COL);
			record.setString(TreeManager.FRAGMENT_NAME_COL, name);
			adapter.updateFragmentRecord(record);
			moduleMgr.nameChanged(oldName, this);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);

		}
		finally {
			lock.release();
		}
	}

	@Override
	public String getTreeName() {
		return moduleMgr.getTreeName();
	}

	@Override
	public boolean contains(Address start, Address end) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.contains(start, end);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean contains(Address addr) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.contains(addr);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean contains(AddressSetView rangeSet) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.contains(rangeSet);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean hasSameAddresses(AddressSetView view) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.hasSameAddresses(view);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressIterator getAddresses(boolean forward) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.getAddresses(forward);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressIterator getAddresses(Address start, boolean forward) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.getAddresses(start, forward);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.getAddressRanges();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return getAddressRanges();
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean atStart) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.getAddressRanges(atStart);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Address getMaxAddress() {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.getMaxAddress();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Address getMinAddress() {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.getMinAddress();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public long getNumAddresses() {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.getNumAddresses();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public int getNumAddressRanges() {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.getNumAddressRanges();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressSet intersect(AddressSetView view) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.intersect(view);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressSet intersectRange(Address start, Address end) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.intersectRange(start, end);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean intersects(Address start, Address end) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.intersects(start, end);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean intersects(AddressSetView set) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.intersects(set);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isEmpty() {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.isEmpty();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressSet subtract(AddressSetView set) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.subtract(set);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressSet union(AddressSetView set) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.union(set);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressSet xor(AddressSetView set) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.xor(set);
		}
		finally {
			lock.release();
		}
	}

	ModuleManager getModuleManager() {
		return moduleMgr;
	}

	void addRange(AddressRange range) {
		addrSet = addrSet.union(new AddressSet(range));
	}

	void removeRange(AddressRange range) {
		addrSet = addrSet.subtract(new AddressSet(range));
	}

	@Override
	public String toString() {
		return addrSet.toString();
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.getAddressRanges(start, forward);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressRange getFirstRange() {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.getFirstRange();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressRange getLastRange() {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.getLastRange();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.getRangeContaining(address);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Iterator<AddressRange> iterator(boolean forward) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.iterator(forward);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Iterator<AddressRange> iterator(Address start, boolean forward) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.iterator(start, forward);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView set) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.findFirstAddressInCommon(set);
		}
		finally {
			lock.release();
		}
	}
}
