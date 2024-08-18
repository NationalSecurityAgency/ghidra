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
import java.util.Objects;

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
		addressSet = new AddressSet();
	}

	/**
	 * Constructor.
	 * @param from the start of the selection
	 * @param to the end of the selection
	 */
	public ProgramSelection(Address from, Address to) {
		this();
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
		addressSet = new AddressSet(setView);
	}

	/**
	 * Construct a new ProgramSelection from the indicated interior selection.
	 * @param sel the interior selection
	 */
	public ProgramSelection(InteriorSelection sel) {
		this(sel.getStartAddress(), sel.getEndAddress());
		interiorSelection = sel;
	}

	/**
	 * Construct a new empty ProgramSelection.
	 * @param addressFactory NOT USED
	 * @deprecated use {@link #ProgramSelection()}
	 */
	@Deprecated(since = "11.2", forRemoval = true)
	public ProgramSelection(AddressFactory addressFactory) {
		this();
	}

	/**
	 * Constructor.
	 * @param addressFactory NOT USED
	 * @param from the start of the selection
	 * @param to the end of the selection
	 */
	@Deprecated(since = "11.2", forRemoval = true)
	public ProgramSelection(AddressFactory addressFactory, Address from, Address to) {
		this(from, to);
	}

	/**
	 * Construct a new ProgramSelection
	 * @param addressFactory NOT USED
	 * @param setView address set for the selection
	 * @deprecated use {@link #ProgramSelection(AddressSetView)}
	 */
	@Deprecated(since = "11.2", forRemoval = true)
	public ProgramSelection(AddressFactory addressFactory, AddressSetView setView) {
		this(setView);
	}

	/**
	 * Construct a new ProgramSelection from the indicated interior selection.
	 * @param addressFactory NOT USED
	 * @param sel the interior selection
	 * @deprecated use {@link #ProgramSelection(InteriorSelection)}s
	 */
	@Deprecated(since = "11.2", forRemoval = true)
	public ProgramSelection(AddressFactory addressFactory, InteriorSelection sel) {
		this(sel);
	}

	/**
	 * Get the interior selection.
	 * @return null if there is no interior selection
	 */
	public InteriorSelection getInteriorSelection() {
		return interiorSelection;
	}

	@Override
	public int hashCode() {
		return Objects.hash(interiorSelection, addressSet);
	}

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

	@Override
	public boolean contains(Address addr) {
		return addressSet.contains(addr);
	}

	@Override
	public boolean contains(Address start, Address end) {
		return addressSet.contains(start, end);
	}

	@Override
	public boolean contains(AddressSetView rangeSet) {
		return addressSet.contains(rangeSet);
	}

	@Override
	public boolean intersects(AddressSetView addrSet) {
		return addressSet != null && addressSet.intersects(addrSet);
	}

	@Override
	public AddressSet intersect(AddressSetView view) {
		return addressSet.intersect(view);
	}

	@Override
	public AddressSet intersectRange(Address start, Address end) {
		return addressSet.intersectRange(start, end);
	}

	@Override
	public boolean isEmpty() {
		return addressSet.isEmpty();
	}

	@Override
	public Address getMinAddress() {
		return addressSet.getMinAddress();
	}

	@Override
	public Address getMaxAddress() {
		return addressSet.getMaxAddress();
	}

	@Override
	public int getNumAddressRanges() {
		return addressSet.getNumAddressRanges();
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean atStart) {
		return addressSet.getAddressRanges(atStart);
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		return addressSet.getAddressRanges();
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return getAddressRanges();
	}

	@Override
	public long getNumAddresses() {
		return addressSet.getNumAddresses();
	}

	@Override
	public AddressIterator getAddresses(boolean forward) {
		return addressSet.getAddresses(forward);
	}

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

	@Override
	public boolean intersects(Address start, Address end) {
		return addressSet.intersects(start, end);
	}

	@Override
	public AddressSet union(AddressSetView view) {
		return addressSet.union(view);
	}

	@Override
	public AddressSet xor(AddressSetView view) {
		return addressSet.xor(view);
	}

	@Override
	public AddressSet subtract(AddressSetView view) {
		return addressSet.subtract(view);
	}

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
