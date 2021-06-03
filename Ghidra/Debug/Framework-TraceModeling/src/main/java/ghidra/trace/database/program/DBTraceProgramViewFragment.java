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
package ghidra.trace.database.program;

import java.util.Iterator;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.trace.database.memory.DBTraceMemoryRegion;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;

// TODO: Destroy this in favor of databased trees?
public class DBTraceProgramViewFragment implements ProgramFragment {
	protected final AbstractDBTraceProgramViewListing listing;
	protected final DBTraceMemoryRegion region;

	public DBTraceProgramViewFragment(AbstractDBTraceProgramViewListing listing,
			DBTraceMemoryRegion region) {
		this.listing = listing;
		this.region = region;
	}

	@Override
	public String getComment() {
		return region.description();
	}

	@Override
	public void setComment(String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getName() {
		return region.getName();
	}

	@Override
	public void setName(String name) throws DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getNumParents() {
		return 1;
	}

	@Override
	public ProgramModule[] getParents() {
		return new ProgramModule[] { listing.rootModule };
	}

	@Override
	public String[] getParentNames() {
		return new String[] { AbstractDBTraceProgramViewListing.TREE_NAME };
	}

	@Override
	public String getTreeName() {
		return AbstractDBTraceProgramViewListing.TREE_NAME;
	}

	@Override
	public boolean contains(Address addr) {
		return region.contains(addr, listing.program.snap);
	}

	@Override
	public boolean contains(Address start, Address end) {
		// Regions are contiguous
		long snap = listing.program.snap;
		return region.contains(start, snap) && region.contains(end, snap);
	}

	@Override
	public boolean contains(AddressSetView rangeSet) {
		long snap = listing.program.snap;
		for (AddressRange range : rangeSet) {
			if (!region.contains(range.getMinAddress(), snap) ||
				!region.contains(range.getMaxAddress(), snap)) {
				return false;
			}
		}
		return true;
	}

	protected AddressSet toAddressSet() {
		return new AddressSet(region.getMinAddress(), region.getMaxAddress());
	}

	@Override
	public boolean isEmpty() {
		return false;
	}

	@Override
	public Address getMinAddress() {
		return region.getMinAddress();
	}

	@Override
	public Address getMaxAddress() {
		return region.getMaxAddress();
	}

	@Override
	public int getNumAddressRanges() {
		return 1;
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		return toAddressSet().getAddressRanges();
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean forward) {
		return toAddressSet().getAddressRanges(forward);
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		return toAddressSet().getAddressRanges(start, forward);
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return toAddressSet().iterator();
	}

	@Override
	public Iterator<AddressRange> iterator(boolean forward) {
		return toAddressSet().iterator(forward);
	}

	@Override
	public Iterator<AddressRange> iterator(Address start, boolean forward) {
		return toAddressSet().iterator(start, forward);
	}

	@Override
	public long getNumAddresses() {
		return toAddressSet().getNumAddresses();
	}

	@Override
	public AddressIterator getAddresses(boolean forward) {
		return toAddressSet().getAddresses(forward);
	}

	@Override
	public AddressIterator getAddresses(Address start, boolean forward) {
		return toAddressSet().getAddresses(start, forward);
	}

	@Override
	public boolean intersects(AddressSetView addrSet) {
		return toAddressSet().intersects(addrSet);
	}

	@Override
	public boolean intersects(Address start, Address end) {
		return toAddressSet().intersects(start, end);
	}

	@Override
	public AddressSet intersect(AddressSetView view) {
		return toAddressSet().intersect(view);
	}

	@Override
	public AddressSet intersectRange(Address start, Address end) {
		return toAddressSet().intersectRange(start, end);
	}

	@Override
	public AddressSet union(AddressSetView addrSet) {
		return toAddressSet().union(addrSet);
	}

	@Override
	public AddressSet subtract(AddressSetView addrSet) {
		return toAddressSet().subtract(addrSet);
	}

	@Override
	public AddressSet xor(AddressSetView addrSet) {
		return toAddressSet().xor(addrSet);
	}

	@Override
	public boolean hasSameAddresses(AddressSetView view) {
		return toAddressSet().hasSameAddresses(view);
	}

	@Override
	public AddressRange getFirstRange() {
		return new AddressRangeImpl(region.getMinAddress(), region.getMaxAddress());
	}

	@Override
	public AddressRange getLastRange() {
		return new AddressRangeImpl(region.getMinAddress(), region.getMaxAddress());
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		if (contains(address)) {
			return getFirstRange();
		}
		return null;
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView set) {
		return toAddressSet().findFirstAddressInCommon(set);
	}

	@Override
	public boolean contains(CodeUnit codeUnit) {
		return contains(codeUnit.getMinAddress(), codeUnit.getMaxAddress());
	}

	@Override
	public CodeUnitIterator getCodeUnits() {
		return listing.getCodeUnits(toAddressSet(), true);
	}

	@Override
	public void move(Address min, Address max) throws NotFoundException {
		throw new UnsupportedOperationException();
	}
}
