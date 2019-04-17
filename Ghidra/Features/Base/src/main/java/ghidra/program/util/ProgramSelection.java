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
package ghidra.program.util;

import java.util.Iterator;

import ghidra.program.model.address.*;

/**
 * Class to define a selection for a program.
 */
public class ProgramSelection implements AddressSetView {

	private AddressSet addressSet;
	private InteriorSelection interiorSelection;

	/**
	 * Construct a new empty ProgramSelection.
	 */
	public ProgramSelection() {
		this((AddressFactory) null);
	}

	/**
	 * Construct a new empty ProgramSelection.
	 * @param addressFactory the address factory for the address set
	 * associated with this program selection.
	 */
	public ProgramSelection(AddressFactory addressFactory) {
		addressSet = new AddressSet();
	}

	/**
	 * Constructor.
	 * @param from the start of the selection
	 * @param to the end of the selection
	 */
	public ProgramSelection(Address from, Address to) {
		this(null, from, to);
	}

	/**
	 * Constructor.
	 * @param addressFactory the address factory for the address set
	 * associated with this program selection.
	 * @param from the start of the selection
	 * @param to the end of the selection
	 */
	public ProgramSelection(AddressFactory addressFactory, Address from, Address to) {
		this(addressFactory);
		if (to.compareTo(from) < 0) {
			Address temp = to;
			to = from;
			from = temp;
		}
		addressSet.addRange(from, to);
	}

	/**
	 * Construct a new ProgramSelection
	 * @param setView address set for the selection
	 */
	public ProgramSelection(AddressSetView setView) {
		this(null, setView);
	}

	/**
	 * Construct a new ProgramSelection
	 * @param addressFactory the address factory for the address set
	 * associated with this program selection.
	 * @param setView address set for the selection
	 */
	public ProgramSelection(AddressFactory addressFactory, AddressSetView setView) {
		addressSet = new AddressSet(setView);
	}

	/**
	 * Construct a new ProgramSelection from the indicated interior selection.
	 * @param addressFactory the address factory for the address set
	 * associated with this program selection.
	 * @param sel the interior selection
	 */
	public ProgramSelection(AddressFactory addressFactory, InteriorSelection sel) {
		this(addressFactory, sel.getStartAddress(), sel.getEndAddress());
		interiorSelection = sel;
	}

	/**
	 * Construct a new ProgramSelection from the indicated interior selection.
	 * @param sel the interior selection
	 */
	public ProgramSelection(InteriorSelection sel) {
		this(null, sel);
	}

	/**
	 * Get the interior selection.
	 * @return null if there is no interior selection
	 */
	public InteriorSelection getInteriorSelection() {
		return interiorSelection;
	}

	/**
	 * Return whether this ProgramSelection is equal to obj.
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (this == obj) {
			return true;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ProgramSelection ps = (ProgramSelection) obj;
		if (interiorSelection != null) {
			return interiorSelection.equals(ps.interiorSelection);
		}
		return addressSet.hasSameAddresses(ps.addressSet);
	}

	/**
	 * Test if the address exists within this set.
	 * <P>
	 * @param addr address to test.
	 * @return true if addr exists in the set, false otherwise.
	 */
	@Override
	public boolean contains(Address addr) {
		return addressSet.contains(addr);
	}

	/**
	 * Test if the given address range is in the set.
	 * <P>
	 * @param start the first address in the range.
	 * @param end the last address in the range.
	 * @return true if entire range is contained within the set,
	 *         false otherwise.
	 */
	@Override
	public boolean contains(Address start, Address end) {
		return addressSet.contains(start, end);
	}

	/**
	 * Test if the given address set is a subset of this set.
	 * <P>
	 * @param rangeSet the set to test.
	 * @return true if the entire set is contained within this set,
	 *         false otherwise.
	 */
	@Override
	public boolean contains(AddressSetView rangeSet) {
		return addressSet.contains(rangeSet);
	}

	/**
	 * Determine if this program selection intersects with the specified address set.
	 *
	 * @param addrSet address set to check intersection with.
	 */
	@Override
	public boolean intersects(AddressSetView addrSet) {
		return addressSet != null ? addressSet.intersects(addrSet) : false;
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#intersect(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public AddressSet intersect(AddressSetView view) {
		return addressSet.intersect(view);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#intersectRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public AddressSet intersectRange(Address start, Address end) {
		return addressSet.intersectRange(start, end);
	}

	/**
	 * Returns true if this set is empty.
	 */
	@Override
	public boolean isEmpty() {
		return addressSet.isEmpty();
	}

	/**
	 * Return the minimum address for this set.
	 */
	@Override
	public Address getMinAddress() {
		return addressSet.getMinAddress();
	}

	/**
	 * Return the maximum address for this set.
	 */
	@Override
	public Address getMaxAddress() {
		return addressSet.getMaxAddress();
	}

	/**
	 * Return the number of address ranges in this set.
	 */
	@Override
	public int getNumAddressRanges() {
		return addressSet.getNumAddressRanges();
	}

	/**
	 * Returns an iterator over the address ranges in this address set.
	 * @param atStart if true, the iterator is positioned at the minimum address.
	 * if false, the iterator is positioned at the maximum address.
	 */
	@Override
	public AddressRangeIterator getAddressRanges(boolean atStart) {
		return addressSet.getAddressRanges(atStart);
	}

	/**
	 * Returns an iterator over the address ranges in this address set.
	 */
	@Override
	public AddressRangeIterator getAddressRanges() {
		return addressSet.getAddressRanges();
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return getAddressRanges();
	}

	/**
	 * Returns the number of addresses in this set.
	 */
	@Override
	public long getNumAddresses() {
		return addressSet.getNumAddresses();
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getAddresses(boolean)
	 */
	@Override
	public AddressIterator getAddresses(boolean forward) {
		return addressSet.getAddresses(forward);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getAddresses(ghidra.program.model.address.Address, boolean)
	 */
	@Override
	public AddressIterator getAddresses(Address start, boolean forward) {
		return addressSet.getAddresses(start, forward);
	}

	/**
	 * Returns true if and only if this set and the given
	 * address set contains exactly the same addresses.
	 * @param asv the address set to compare with this one.
	 * @return true if the specified set has the same addresses.
	 */
	@Override
	public boolean hasSameAddresses(AddressSetView asv) {
		if (asv instanceof ProgramSelection) {
			return equals(asv);
		}
		return addressSet.hasSameAddresses(asv);
	}

	/**
	 * @see AddressSetView#intersects(Address, Address)
	 */
	@Override
	public boolean intersects(Address start, Address end) {
		return addressSet.intersects(start, end);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#union(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public AddressSet union(AddressSetView view) {
		return addressSet.union(view);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#xor(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public AddressSet xor(AddressSetView view) {
		return addressSet.xor(view);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#subtract(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public AddressSet subtract(AddressSetView view) {
		return addressSet.subtract(view);
	}

	/* (non Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		if (interiorSelection != null) {
			return "Interior Selection: " + interiorSelection;
		}
		return "ProgramSelection: " + addressSet;
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		return addressSet.getAddressRanges(start, forward);
	}

	@Override
	public AddressRange getFirstRange() {
		return addressSet.getFirstRange();
	}

	@Override
	public AddressRange getLastRange() {
		return addressSet.getLastRange();
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		return addressSet.getRangeContaining(address);
	}

	@Override
	public Iterator<AddressRange> iterator(boolean forward) {
		return addressSet.iterator(forward);
	}

	@Override
	public Iterator<AddressRange> iterator(Address start, boolean forward) {
		return addressSet.iterator(start, forward);
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView set) {
		return addressSet.findFirstAddressInCommon(set);
	}

}
