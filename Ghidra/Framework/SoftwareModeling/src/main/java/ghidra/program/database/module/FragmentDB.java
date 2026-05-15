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

import db.DBRecord;
import db.Field;
import ghidra.program.database.DbObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.Lock;
import ghidra.util.Lock.Closeable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;

/**
 *
 * Database implementation for Fragment.
 *
 */
class FragmentDB extends DbObject implements ProgramFragment {

	private DBRecord record;
	private ModuleManager moduleMgr;
	private FragmentDBAdapter fragmentAdapter;
	private ParentChildDBAdapter parentChildAdapter;
	private AddressSet addrSet;
	private Lock lock;

	/**
	 * Constructor
	 * @param moduleMgr module manager
	 * @param record fragment record
	 * @param addrSet fragment address set
	 */
	FragmentDB(ModuleManager moduleMgr, DBRecord record, AddressSet addrSet) {
		super(record.getKey());
		this.moduleMgr = moduleMgr;
		this.record = record;
		this.addrSet = addrSet;
		fragmentAdapter = moduleMgr.getFragmentAdapter();
		parentChildAdapter = moduleMgr.getParentChildAdapter();
		lock = moduleMgr.getLock();
	}

	@Override
	protected boolean refresh() {
		try {
			DBRecord rec = fragmentAdapter.getFragmentRecord(key);
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
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return moduleMgr.getCodeUnits(this);
		}
	}

	@Override
	public String getComment() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return record.getString(FragmentDBAdapter.FRAGMENT_COMMENTS_COL);
		}
	}

	@Override
	public String getName() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return record.getString(FragmentDBAdapter.FRAGMENT_NAME_COL);
		}
	}

	@Override
	public int getNumParents() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			Field[] keys =
				parentChildAdapter.getParentChildKeys(-key, ParentChildDBAdapter.CHILD_ID_COL);
			return keys.length;
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
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
		try (Closeable c = lock.write()) {
			checkDeleted();
			moduleMgr.move(this, min, max);
		}
	}

	@Override
	public void setComment(String comment) {
		try (Closeable c = lock.write()) {
			checkDeleted();
			String oldComments = record.getString(FragmentDBAdapter.FRAGMENT_COMMENTS_COL);
			if (oldComments == null || !oldComments.equals(comment)) {
				record.setString(FragmentDBAdapter.FRAGMENT_COMMENTS_COL, comment);
				try {
					fragmentAdapter.updateFragmentRecord(record);
					moduleMgr.commentsChanged(oldComments, this);
				}
				catch (IOException e) {
					moduleMgr.dbError(e);
				}
			}

		}
	}

	@Override
	public void setName(String name) throws DuplicateNameException {
		try (Closeable c = lock.write()) {
			refreshIfNeeded();
			DBRecord r = fragmentAdapter.getFragmentRecord(name);
			if (r != null) {
				if (key != r.getKey()) {
					throw new DuplicateNameException(name + " already exists");
				}
				return; // no changes
			}
			if (fragmentAdapter.getFragmentRecord(name) != null) {
				throw new DuplicateNameException(name + " already exists");
			}
			String oldName = record.getString(FragmentDBAdapter.FRAGMENT_NAME_COL);
			record.setString(FragmentDBAdapter.FRAGMENT_NAME_COL, name);
			fragmentAdapter.updateFragmentRecord(record);
			moduleMgr.nameChanged(oldName, this);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);

		}
	}

	@Override
	public String getTreeName() {
		return moduleMgr.getTreeName();
	}

	@Override
	public boolean contains(Address start, Address end) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.contains(start, end);
		}
	}

	@Override
	public boolean contains(Address addr) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.contains(addr);
		}
	}

	@Override
	public boolean contains(AddressSetView rangeSet) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.contains(rangeSet);
		}
	}

	@Override
	public boolean hasSameAddresses(AddressSetView view) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.hasSameAddresses(view);
		}
	}

	@Override
	public AddressIterator getAddresses(boolean forward) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.getAddresses(forward);
		}
	}

	@Override
	public AddressIterator getAddresses(Address start, boolean forward) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.getAddresses(start, forward);
		}
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.getAddressRanges();
		}
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return getAddressRanges();
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean atStart) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.getAddressRanges(atStart);
		}
	}

	@Override
	public Address getMaxAddress() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.getMaxAddress();
		}
	}

	@Override
	public Address getMinAddress() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.getMinAddress();
		}
	}

	@Override
	public long getNumAddresses() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.getNumAddresses();
		}
	}

	@Override
	public int getNumAddressRanges() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.getNumAddressRanges();
		}
	}

	@Override
	public AddressSet intersect(AddressSetView view) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.intersect(view);
		}
	}

	@Override
	public AddressSet intersectRange(Address start, Address end) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.intersectRange(start, end);
		}
	}

	@Override
	public boolean intersects(Address start, Address end) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.intersects(start, end);
		}
	}

	@Override
	public boolean intersects(AddressSetView set) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.intersects(set);
		}
	}

	@Override
	public boolean isEmpty() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.isEmpty();
		}
	}

	@Override
	public AddressSet subtract(AddressSetView set) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.subtract(set);
		}
	}

	@Override
	public AddressSet union(AddressSetView set) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.union(set);
		}
	}

	@Override
	public AddressSet xor(AddressSetView set) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.xor(set);
		}
	}

	ModuleManager getModuleManager() {
		return moduleMgr;
	}

	void addRange(AddressRange range) {
		addrSet.add(range);
	}

	void removeRange(AddressRange range) {
		addrSet.delete(range);
	}

	@Override
	public String toString() {
		String name = record.getString(FragmentDBAdapter.FRAGMENT_NAME_COL);
		return name + ": " + addrSet.toString();
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.getAddressRanges(start, forward);
		}
	}

	@Override
	public AddressRange getFirstRange() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.getFirstRange();
		}
	}

	@Override
	public AddressRange getLastRange() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.getLastRange();
		}
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.getRangeContaining(address);
		}
	}

	@Override
	public Iterator<AddressRange> iterator(boolean forward) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.iterator(forward);
		}
	}

	@Override
	public Iterator<AddressRange> iterator(Address start, boolean forward) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.iterator(start, forward);
		}
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView set) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return addrSet.findFirstAddressInCommon(set);
		}
	}

	@Override
	public boolean isDeleted() {
		return isDeleted(lock);
	}
}
