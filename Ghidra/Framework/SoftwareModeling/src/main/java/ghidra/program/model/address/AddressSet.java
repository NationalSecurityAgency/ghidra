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
package ghidra.program.model.address;

import java.util.*;

import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.RedBlackEntry;
import ghidra.util.datastruct.RedBlackTree;

/**
 * Class for storing sets of addresses.  This implementation uses a red-black tree where each
 * entry node in the tree stores an address range.  The key for an entry node is the minimum address
 * of the range and the value is the maximum address of the range.
 */

public class AddressSet implements AddressSetView {
	private final static double LOGBASE2 = Math.log(2);
	private RedBlackTree<Address, Address> rbTree = new RedBlackTree<>();
	private RedBlackEntry<Address, Address> lastNode;
	private long addressCount = 0;

	/**
	 * Create a new empty Address Set.
	 */
	public AddressSet() {
	}

	/**
	 * Create a new empty Address Set.
	 * @param factory NOT USED.
	 * @deprecated use {@link #AddressSet()}  (will be kept until at least Ghidra 6.2)
	 */
	@Deprecated
	public AddressSet(AddressFactory factory) {
		this();
	}

	/**
	 * Create a new Address Set from an address range.
	 * @param range the range of addresses to include in this set.
	 */
	public AddressSet(AddressRange range) {
		add(range);
	}

	/**
	 * Create a new Address Set from an address range.
	 * @param factory NOT USED.
	 * @param range the range of addresses to include in this set.
	 * @deprecated use {@link #AddressSet(AddressRange)}  (will be kept until at least Ghidra 6.2)
	 */
	@Deprecated
	public AddressSet(AddressFactory factory, AddressRange range) {
		add(range);
	}

	/**
	 * Creates a new Address set containing a single range
	 * @param start the start address of the range
	 * @param end the end address of the range
	 * @throws IllegalArgumentException if the start and end addresses are in different spaces.  To
	 * avoid this, use the constructor  {@link #AddressSet(Program, Address, Address)}
	 */
	public AddressSet(Address start, Address end) {
		addRange(start, end);
	}

	/**
	 * Creates a new Address set containing a single range
	 * @param start the start address of the range
	 * @param end the end address of the range
	 * @param factory NOT USED.
	 * @deprecated use {@link #AddressSet(Address, Address)}  (will be kept until at least Ghidra 6.2)
	 */
	@Deprecated
	public AddressSet(AddressFactory factory, Address start, Address end) {
		addRange(start, end);
	}

	/**
	 * Creates a new Address set containing a single range
	 * @param start the start address of the range
	 * @param end the end address of the range
	 * @param program the program whose AddressFactory is used to resolve address ranges where the
	 * start and end are in different address spaces. If you use the constructor with just the
	 * start and end address and the addresses are in different spaces, you would get an
	 * IllegalArgumentException.
	 */
	public AddressSet(Program program, Address start, Address end) {
		addRange(program, start, end);
	}

	/**
	 * Create a new Address Set from an existing Address Set.
	 * @param set Existing Address Set to clone.
	 * @param factory NOT USED.
	 * @deprecated use {@link #AddressSet(AddressSetView)}  (will be kept until at least Ghidra 6.2)
	 */
	@Deprecated
	public AddressSet(AddressFactory factory, AddressSetView set) {
		add(set);
	}

	/**
	 * Create a new Address Set from an existing Address Set.
	 * @param set Existing Address Set to clone.
	 */
	public AddressSet(AddressSetView set) {
		add(set);
	}

	/**
	 * Create a new Address containing a single address.
	 * @param addr the address to be included in this address set.
	 * @param factory NOT USED.
	 * @deprecated use {@link #AddressSet(Address)}  (will be kept until at least Ghidra 6.2)
	 */
	@Deprecated
	public AddressSet(AddressFactory factory, Address addr) {
		this(addr, addr);
	}

	/**
	 * Create a new Address containing a single address.
	 * @param addr the address to be included in this address set.
	 */
	public AddressSet(Address addr) {
		this(addr, addr);
	}

	/**
	 * Adds the given address to this set.
	 * @param address the address to add
	 */
	public final void add(Address address) {
		this.addRange(address, address);
	}

	/**
	 * Add an address range to this set.
	 * @param range the range to add.
	 */
	public final void add(AddressRange range) {
		if (range == null) {
			return;
		}
		add(range.getMinAddress(), range.getMaxAddress());
	}

	/**
	 * Adds the range to this set
	 * @param start the start address of the range to add
	 * @param end the end address of the range to add
	 */
	public void add(Address start, Address end) {
		checkValidRange(start, end);

		if (lastNode != null && !lastNode.isDisposed()) {
			Address value = lastNode.getValue();
			if (contains(lastNode, start) || value.isSuccessor(start)) {
				if (end.compareTo(value) > 0) {
					updateRangeEndAddress(lastNode, end);
					consumeFollowOnNodes(lastNode);
				}
				return;
			}
		}

		if (rbTree.isEmpty()) {
			lastNode = createRangeNode(start, end);
			return;
		}

		if (start.compareTo(rbTree.getLast().getKey()) > 0) {
			RedBlackEntry<Address, Address> last = rbTree.getLast();
			Address value = last.getValue();
			if (contains(last, start) || value.isSuccessor(start)) {
				if (end.compareTo(value) > 0) {
					updateRangeEndAddress(last, end);
				}
			}
			else {
				lastNode = createRangeNode(start, end);
			}
			return;
		}

		lastNode = rbTree.getEntryLessThanEqual(start);
		if (lastNode == null) {
			lastNode = createRangeNode(start, end);
			consumeFollowOnNodes(lastNode);
			return;
		}

		Address nodeEnd = lastNode.getValue();
		if (nodeEnd.compareTo(start) >= 0 || nodeEnd.isSuccessor(start)) {
			if (end.compareTo(nodeEnd) > 0) {
				updateRangeEndAddress(lastNode, end);
				consumeFollowOnNodes(lastNode);
			}
			return;
		}

		lastNode = createRangeNode(start, end);
		consumeFollowOnNodes(lastNode);

	}

	/**
	 * Adds the range to this set
	 * @param start the start address of the range to add
	 * @param end the end address of the range to add
	 * @throws IllegalArgumentException if the start and end addresses are in different spaces.  To
	 * avoid this, use the constructor  {@link #addRange(Program, Address, Address)}
	 */
	public void addRange(Address start, Address end) {
		add(start, end);
	}

	/**
	 * Adds a range of addresses to this set.
	 * @param program program whose AddressFactory is used to resolve address ranges that span
	 * multiple address spaces.
	 * @param start the start address of the range to add
	 * @param end the end address of the range to add
	 */
	public void addRange(Program program, Address start, Address end) {
		if (start.getAddressSpace().equals(end.getAddressSpace())) {
			addRange(start, end);
			return;
		}
		AddressFactory addressFactory = program.getAddressFactory();
		add(addressFactory.getAddressSet(start, end));
	}

	/**
	 * Add all addresses of the given AddressSet to this set.
	 * @param addressSet set of addresses to add.
	 */
	public final void add(AddressSetView addressSet) {
		if (addressSet == null) {
			return;
		}

		if (useLinearAlgorithm(addressSet)) {
			AddressSet newSet = mergeSets(addressSet);
			rbTree = newSet.rbTree;
			addressCount = newSet.addressCount;
			lastNode = null;
		}
		else {
			AddressRangeIterator it = addressSet.getAddressRanges();
			while (it.hasNext()) {
				AddressRange range = it.next();
				addRange(range.getMinAddress(), range.getMaxAddress());
			}
		}
	}

	/**
	 * Deletes an address range from this set.
	 * @param range AddressRange to remove from this set
	 */
	public final void delete(AddressRange range) {
		deleteRange(range.getMinAddress(), range.getMaxAddress());
	}

	/**
	 * Deletes a range of addresses from this set
	 * @param start the starting address of the range to be removed
	 * @param end the ending address of the range to be removed (inclusive)
	 */
	public final void delete(Address start, Address end) {
		if (start.compareTo(end) > 0) {
			throw new IllegalArgumentException(
				"Start address (" + start + ") is greater than end address (" + end + ")");
		}
		RedBlackEntry<Address, Address> entry = rbTree.getEntryLessThanEqual(start);
		if (entry == null) {
			entry = rbTree.getFirst();
		}
		else if (entry.getValue().compareTo(start) < 0) {
			entry = entry.getSuccessor();
		}

		while (entry != null) {
			Address minRange = entry.getKey();
			Address maxRange = entry.getValue();
			switch (compareRange(start, end, minRange, maxRange)) {
				case RANGE1_COMPLETELY_AFTER_RANGE2:
					// delete range is after current range so ok, move to next range to consider
					entry = entry.getSuccessor();
					break;
				case RANGE1_COMPLETELY_BEFORE_RANGE2:
					// delete range is before range, so done
					return;
				case RANGE1_EQUALS_RANGE2:
					// delete range matches range, delete it and done
					deleteRangeNode(entry);
					return;
				case RANGE1_STARTS_AT_RANGE2_ENDS_AFTER_RANGE2:
				case RANGE1_STARTS_BEFORE_RANGE2_ENDS_AFTER_RANGE2:
				case RANGE1_STARTS_BEFORE_RANGE2_ENDS_AT_RANGE2_END:
					// delete range spans current range, delete current range and move to next range
					entry = deleteRangeNode(entry);
					break;
				case RANGE1_STARTS_AT_RANGE2_ENDS_BEFORE_RANGE2:
				case RANGE1_STARTS_BEFORE_RANGE2_ENDS_INSIDE_RANGE2:
					// delete first part of range and then done.
					deleteRangeNode(entry);
					createRangeNode(end.next(), maxRange);
					return;
				case RANGE1_STARTS_INSIDE_RANGE2_ENDS_AFTER_RANGE2:
				case RANGE1_STARTS_INSIDE_RANGE2_ENDS_AT_RANGE2:
					// delete back part of range, and get next range
					updateRangeEndAddress(entry, start.previous());
					entry = entry.getSuccessor();
					break;
				case RANGE1_STARTS_INSIDE_RANGE2_ENDS_INSIDE_RANGE2:
					// delete range is inside, update current range and add in back part of range
					updateRangeEndAddress(entry, start.previous());
					createRangeNode(end.next(), maxRange);
					return;

			}
		}

	}

	/**
	 * Deletes a range of addresses from this set
	 * @param start the starting address of the range to be removed
	 * @param end the ending address of the range to be removed
	 */
	public final void deleteRange(Address start, Address end) {
		delete(start, end);
	}

	/**
	 * Delete all addresses in the given AddressSet from this set.
	 * @param addressSet set of addresses to remove from this set.
	 */
	public final void delete(AddressSetView addressSet) {
		if (addressSet == null || addressSet.getNumAddressRanges() == 0) {
			return;
		}
		if (isEmpty()) {
			return;
		}

		if (useLinearAlgorithm(addressSet)) {
			AddressSet newSet = deleteSets(addressSet);
			rbTree = newSet.rbTree;
			addressCount = newSet.addressCount;
			lastNode = null;
		}
		else {
			for (AddressRange addressRange : addressSet) {
				delete(addressRange);
			}
		}
	}

	/**
	 * Removes all addresses from the set.
	 */
	public void clear() {
		rbTree.removeAll();
		lastNode = null;
		addressCount = 0;
	}

	/**
	 * Returns a string displaying the ranges in this set.
	 * @return a string displaying the ranges in this set.
	 */
	public String printRanges() {
		StringBuffer buffy = new StringBuffer("[");
		for (AddressRange range : this) {
			buffy.append(range);
			buffy.append(" ");
		}
		buffy.append("]");
		return buffy.toString();
	}

	/**
	 * Returns a list of the AddressRanges in this set.
	 * @return  a list of the AddressRanges in this set.
	 */
	public List<AddressRange> toList() {
		ArrayList<AddressRange> list = new ArrayList<>();
		for (AddressRange range : this) {
			list.add(range);
		}
		return list;
	}

	@Override
	public final boolean contains(Address address) {
		// See if there is a tree node whose range encapsulates the given address.
		RedBlackEntry<Address, Address> entry = rbTree.getEntryLessThanEqual(address);
		if (entry == null) {
			return false;
		}
		return address.compareTo(entry.getValue()) <= 0;
	}

	@Override
	public final boolean contains(Address start, Address end) {
		// See if there is a tree node whose range encapsulates the given range.
		RedBlackEntry<Address, Address> entry = rbTree.getEntryLessThanEqual(start);
		if (entry == null) {
			return false;
		}

		return end.compareTo(entry.getValue()) <= 0;
	}

	@Override
	public final boolean contains(AddressSetView addrSet) {
		if (addrSet.getNumAddressRanges() == 0) {
			return true;
		}
		if (getNumAddressRanges() == 0) {
			return false;
		}

		Address thisMinAddr = getMinAddress();
		Address thatMinAddr = addrSet.getMinAddress();
		if (thisMinAddr.compareTo(thatMinAddr) > 0) {
			return false;
		}
		Address thisMaxAddr = getMaxAddress();
		Address thatMaxAddr = addrSet.getMaxAddress();
		if (thisMaxAddr.compareTo(thatMaxAddr) < 0) {
			return false;
		}

		if (useLinearAlgorithm(addrSet)) {
			return containsLinear(addrSet);
		}
		return containsBinary(addrSet);

	}

	@Override
	public final boolean hasSameAddresses(AddressSetView addrSet) {
		return equals(addrSet);
	}

	@Override
	public final boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}

		if (obj == this) {
			return true;
		}

		if (!(obj instanceof AddressSetView)) {
			return false;
		}
		AddressSetView set = (AddressSetView) obj;

		if (this.getNumAddresses() != set.getNumAddresses()) {
			return false;
		}

		// if don't have same number of ranges, not equal
		if (this.getNumAddressRanges() != set.getNumAddressRanges()) {
			return false;
		}

		AddressRangeIterator otherRanges = set.getAddressRanges();
		AddressRangeIterator myRanges = getAddressRanges();
		while (myRanges.hasNext()) {
			AddressRange myRange = myRanges.next();
			AddressRange otherRange = otherRanges.next();
			if (!myRange.equals(otherRange)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public int hashCode() {
		if (isEmpty()) {
			return 0;
		}
		return getMinAddress().hashCode() + getMaxAddress().hashCode();
	}

	@Override
	public boolean intersects(AddressSetView addrSet) {
		int thisSize = getNumAddressRanges();
		int thatSize = addrSet.getNumAddressRanges();

		if (thisSize == 0 || thatSize == 0) {
			return false;
		}

		// if this address set has fewer ranges, swap for possible more efficient computation.
		if (thisSize < thatSize) {
			return addrSet.intersects(this);
		}

		if (useLinearAlgorithm(addrSet)) {
			return intersectsLinear(addrSet);
		}
		return intersectsBinary(addrSet);
	}

	@Override
	public final AddressSet intersectRange(Address start, Address end) {
		return intersectRange(start, end, new AddressSet());
	}

	@Override
	public final AddressSet intersect(AddressSetView addrSet) {
		if (addrSet == null || addrSet.isEmpty() || isEmpty()) {
			return new AddressSet();
		}
		int thisSize = getNumAddressRanges();
		int thatSize = addrSet.getNumAddressRanges();

		// if this address set has fewer ranges, swap for possible more efficient computation
		if (thisSize < thatSize) {
			return addrSet.intersect(this);
		}

		if (useLinearAlgorithm(addrSet)) {
			return intersectLinear(addrSet);
		}
		return intersectBinary(addrSet);
	}

	@Override
	public final AddressSet union(AddressSetView addrSet) {
		return mergeSets(addrSet);
	}

	@Override
	public final AddressSet subtract(AddressSetView addrSet) {
		if (addrSet.getNumAddressRanges() == 0) {
			return new AddressSet(this);
		}
		return deleteSets(addrSet);
	}

	@Override
	public boolean isEmpty() {
		return rbTree.isEmpty();
	}

	@Override
	public Address getMinAddress() {
		if (rbTree.isEmpty()) {
			return null;
		}
		return rbTree.getFirst().getKey();
	}

	@Override
	public Address getMaxAddress() {
		if (rbTree.isEmpty()) {
			return null;
		}
		return rbTree.getLast().getValue();
	}

	@Override
	public int getNumAddressRanges() {
		return rbTree.size();
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return getAddressRanges();
	}

	@Override
	public Iterator<AddressRange> iterator(boolean forward) {
		return getAddressRanges(forward);
	}

	@Override
	public Iterator<AddressRange> iterator(Address start, boolean forward) {
		return getAddressRanges(start, forward);
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		return new AddressRangeIteratorAdapter(rbTree.iterator());
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean forward) {
		Iterator<RedBlackEntry<Address, Address>> iterator = rbTree.iterator(forward);
		return new AddressRangeIteratorAdapter(iterator);
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		RedBlackEntry<Address, Address> entry = rbTree.getEntryLessThanEqual(start);
		if (entry == null) {
			if (forward) {
				return new AddressRangeIteratorAdapter(rbTree.iterator());
			}
			return new EmptyAddressRangeIterator();
		}
		if (forward && !contains(entry, start)) {
			entry = entry.getSuccessor();
		}
		Iterator<RedBlackEntry<Address, Address>> iterator = rbTree.iterator(entry, forward);
		return new AddressRangeIteratorAdapter(iterator);
	}

	@Override
	public long getNumAddresses() {
		return addressCount;
	}

	@Override
	public AddressIterator getAddresses(boolean forward) {
//		return new ForwardAddressIterator(null);
		return new MyAddressIterator(null, forward);
	}

	@Override
	public AddressIterator getAddresses(Address start, boolean forward) {
		return new MyAddressIterator(start, forward);
	}

	@Override
	public boolean intersects(Address start, Address end) {
		RedBlackEntry<Address, Address> entry = rbTree.getEntryLessThanEqual(end);
		if (entry == null) {
			return false;
		}
		return start.compareTo(entry.getValue()) <= 0;
	}

	@Override
	public AddressSet xor(AddressSetView addrSet) {
		if (isEmpty()) {
			return new AddressSet(addrSet);
		}
		return xorSets(addrSet);
	}

	@Override
	public final String toString() {
		int size = getNumAddressRanges();

		if (size == 0) {
			return ("[empty]\n");
		}
		//else if (size == 1) {
		return printRanges();
//		}
//
//		AddressRange startRange = getRange(rbTree.getFirst());
//		AddressRange endRange = getRange(rbTree.getLast());
//		return "[" + startRange + "..." + endRange + "]";
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		RedBlackEntry<Address, Address> entry = rbTree.getEntryLessThanEqual(address);
		if (entry != null && contains(entry, address)) {
			return new AddressRangeImpl(entry.getKey(), entry.getValue());
		}
		return null;
	}

	@Override
	public AddressRange getFirstRange() {
		RedBlackEntry<Address, Address> first = rbTree.getFirst();
		if (first != null) {
			return new AddressRangeImpl(first.getKey(), first.getValue());
		}
		return null;
	}

	@Override
	public AddressRange getLastRange() {
		RedBlackEntry<Address, Address> last = rbTree.getLast();
		if (last != null) {
			return new AddressRangeImpl(last.getKey(), last.getValue());
		}
		return null;
	}

	private boolean intersectsBinary(AddressSetView addrSet) {
		for (AddressRange range : addrSet) {
			if (intersects(range.getMinAddress(), range.getMaxAddress())) {
				return true;
			}
		}
		return false;
	}

	private boolean intersectsLinear(AddressSetView addrSet) {
		RedBlackEntry<Address, Address> entry =
			rbTree.getEntryLessThanEqual(addrSet.getMinAddress());
		if (entry == null) {
			entry = rbTree.getFirst();
		}

		Iterator<AddressRange> iterator = addrSet.iterator();
		while (iterator.hasNext()) {
			AddressRange range = iterator.next();
			while (range.compareTo(entry.getValue()) > 0) {
				entry = entry.getSuccessor();
				if (entry == null) {
					return false;
				}
			}
			if (range.getMaxAddress().compareTo(entry.getKey()) >= 0) {
				return true;
			}
		}
		return false;
	}

	private boolean containsLinear(AddressSetView addrSet) {
		RedBlackEntry<Address, Address> entry =
			rbTree.getEntryLessThanEqual(addrSet.getMinAddress());
		if (entry == null) {
			return false;
		}
		Iterator<AddressRange> iterator = addrSet.iterator();
		while (iterator.hasNext()) {
			AddressRange range = iterator.next();
			while (range.compareTo(entry.getValue()) > 0) {
				entry = entry.getSuccessor();
				if (entry == null) {
					return false;
				}
			}
			if (range.getMaxAddress().compareTo(entry.getValue()) > 0) {
				return false;
			}
		}
		return true;
	}

	// if (M+N) < Nlog(M), then perform two different algorithms.
	//        where:
	//			log is base 2,
	//			M -> this
	//			N -> that

	/**
	 * Determines if the optimal algorithm for an operation.  Generally set operations can be done
	 * either by applying each range of the given address set to this set OR by linearly visiting
	 * each range in both this set and the other set.  The first approach involves doing a
	 * binary search in this set for each range in the given set costing Nlog(M) operations where
	 * N is the size of this set and M is the size of the other set.  The second approach involves
	 * visiting every range in both sets in order so the cost is N + M.  Therefor, if N+M is less
	 * than Nlog(M), we should use a linear algorithm.
	 *
	 * @param set the other address set to operate against.
	 * @return true if a linear algorithm will likely be faster that a series of binary searches.
	 */
	private boolean useLinearAlgorithm(AddressSetView set) {
		int thisSize = getNumAddressRanges();
		int thatSize = set.getNumAddressRanges();
		return (thisSize + thatSize <= thatSize * Math.log(thisSize) / LOGBASE2);
	}

	private boolean containsBinary(AddressSetView addrSet) {
		for (AddressRange range : addrSet) {
			if (!contains(range.getMinAddress(), range.getMaxAddress())) {
				return false;
			}
		}
		return true;
	}

	private AddressSet intersectRange(Address start, Address end, AddressSet set) {
		if (!start.getAddressSpace().equals(end.getAddressSpace())) {
			if (start.compareTo(end) > 0) {
				Address tmp = start;
				start = end;
				end = tmp;
			}
		}
		if (start.compareTo(end) > 0) {
			throw new IllegalArgumentException("Start address must be less than or equal to " +
				"end address:  Start " + start + "   end = " + end);
		}

		RedBlackEntry<Address, Address> entry = rbTree.getEntryLessThanEqual(start);
		if (entry != null) {
			if (entry.getValue().compareTo(start) >= 0) {
				set.addRange(start, min(end, entry.getValue()));
			}
			entry = entry.getSuccessor();
		}
		else {
			entry = rbTree.getFirst();
		}
		while (entry != null) {
			if (entry.getKey().compareTo(end) > 0) {
				break;
			}
			set.addRange(entry.getKey(), min(end, entry.getValue()));
			entry = entry.getSuccessor();
		}

		return set;
	}

	private AddressSet intersectLinear(AddressSetView addrSet) {
		Iterator<AddressRange> thisIt = iterator(addrSet.getMinAddress(), true);
		Iterator<AddressRange> thatIt = addrSet.iterator();

		AddressSet set = new AddressSet();

		if (!thisIt.hasNext() || !thatIt.hasNext()) {
			return set;
		}

		AddressRange thisRange = thisIt.next();
		AddressRange thatRange = thatIt.next();
		while (true) {
			if (thisRange.intersects(thatRange)) {
				AddressRange intersection = thisRange.intersect(thatRange);
				set.add(intersection);
			}

			if (thisRange.getMaxAddress().compareTo(thatRange.getMaxAddress()) <= 0) {
				if (!thisIt.hasNext()) {
					break;
				}
				thisRange = thisIt.next();
			}
			else {
				if (!thatIt.hasNext()) {
					break;
				}
				thatRange = thatIt.next();
			}
		}
		return set;
	}

	private AddressSet intersectBinary(AddressSetView addrSet) {
		AddressSet set = new AddressSet();

		for (AddressRange range : addrSet) {
			intersectRange(range.getMinAddress(), range.getMaxAddress(), set);
		}
		return set;
	}

	private Address min(Address addr1, Address addr2) {
		if (addr1.compareTo(addr2) <= 0) {
			return addr1;
		}
		return addr2;
	}

	private RangeCompare compareRange(AddressRange range1, AddressRange range2) {
		Address minAddr1 = range1.getMinAddress();
		Address maxAddr1 = range1.getMaxAddress();
		Address minAddr2 = range2.getMinAddress();
		Address maxAddr2 = range2.getMaxAddress();
		return compareRange(minAddr1, maxAddr1, minAddr2, maxAddr2);
	}

	// @formatter:off
	enum RangeCompare {
		/*  ____
		   |    |
		           |____|
		*/
		RANGE1_COMPLETELY_BEFORE_RANGE2,
		/*   _____
		    |     |
		      |_____|

		*/
		RANGE1_STARTS_BEFORE_RANGE2_ENDS_INSIDE_RANGE2,
		/*   _______
		    |       |	   |
		       |____|       |
		*/
		RANGE1_STARTS_BEFORE_RANGE2_ENDS_AT_RANGE2_END,
		/*   ________
		    |        |
		      |____|
		*/
		RANGE1_STARTS_BEFORE_RANGE2_ENDS_AFTER_RANGE2,
		/*   _____
	    		|     |
	        |________|
		*/
		RANGE1_STARTS_AT_RANGE2_ENDS_BEFORE_RANGE2,
		/*   ________
	        |        |
	        |________|
	    */
		RANGE1_EQUALS_RANGE2,
		/*   _______
	        |       |
	        |____|
	    */
		RANGE1_STARTS_AT_RANGE2_ENDS_AFTER_RANGE2,
		/*     ____
	          |    |
	        |______|
	    */
		RANGE1_STARTS_INSIDE_RANGE2_ENDS_AT_RANGE2,
		/*     ____
	          |    |
	        |_________|
	    */
		RANGE1_STARTS_INSIDE_RANGE2_ENDS_INSIDE_RANGE2,
		/*     ______
	          |      |
	        |____|
	    */
		RANGE1_STARTS_INSIDE_RANGE2_ENDS_AFTER_RANGE2,
		/*          ________
	               |        |
	        |____|
	    */
		RANGE1_COMPLETELY_AFTER_RANGE2,
	}
	// @formatter:on
	private RangeCompare compareRange(Address minAddr1, Address maxAddr1, Address minAddr2,
			Address maxAddr2) {

		if (maxAddr1.compareTo(minAddr2) < 0) {
			return RangeCompare.RANGE1_COMPLETELY_BEFORE_RANGE2;
		}
		if (minAddr1.compareTo(maxAddr2) > 0) {
			return RangeCompare.RANGE1_COMPLETELY_AFTER_RANGE2;
		}
		int startCompare = minAddr1.compareTo(minAddr2);
		int endCompare = maxAddr1.compareTo(maxAddr2);

		if (startCompare < 0) {
			if (endCompare < 0) {
				return RangeCompare.RANGE1_STARTS_BEFORE_RANGE2_ENDS_INSIDE_RANGE2;
			}
			else if (endCompare > 0) {
				return RangeCompare.RANGE1_STARTS_BEFORE_RANGE2_ENDS_AFTER_RANGE2;
			}
			return RangeCompare.RANGE1_STARTS_BEFORE_RANGE2_ENDS_AT_RANGE2_END;
		}
		if (startCompare > 0) {
			if (endCompare < 0) {
				return RangeCompare.RANGE1_STARTS_INSIDE_RANGE2_ENDS_INSIDE_RANGE2;
			}
			else if (endCompare > 0) {
				return RangeCompare.RANGE1_STARTS_INSIDE_RANGE2_ENDS_AFTER_RANGE2;
			}
			return RangeCompare.RANGE1_STARTS_INSIDE_RANGE2_ENDS_AT_RANGE2;

		}

		if (endCompare < 0) {
			return RangeCompare.RANGE1_STARTS_AT_RANGE2_ENDS_BEFORE_RANGE2;
		}
		else if (endCompare > 0) {
			return RangeCompare.RANGE1_STARTS_AT_RANGE2_ENDS_AFTER_RANGE2;
		}
		return RangeCompare.RANGE1_EQUALS_RANGE2;

	}

	private AddressSet deleteSets(AddressSetView addrSet) {
		AddressSet newSet = new AddressSet();

		AddressRangeIterator rangeIt = getAddressRanges();
		AddressRangeIterator deleteRangeIt = addrSet.getAddressRanges();

		AddressRange range = rangeIt.hasNext() ? rangeIt.next() : null;
		AddressRange deleteRange = deleteRangeIt.hasNext() ? deleteRangeIt.next() : null;

		while (range != null && deleteRange != null) {
			switch (compareRange(deleteRange, range)) {
				case RANGE1_COMPLETELY_BEFORE_RANGE2:
					// delete range is complete before range so not relevant, get next delete range
					deleteRange = deleteRangeIt.hasNext() ? deleteRangeIt.next() : null;
					break;
				case RANGE1_COMPLETELY_AFTER_RANGE2:
					// delete range completely after current range, so save currentRange and get next range.
					newSet.add(range);
					range = rangeIt.hasNext() ? rangeIt.next() : null;
					break;
				case RANGE1_EQUALS_RANGE2:
				case RANGE1_STARTS_AT_RANGE2_ENDS_AFTER_RANGE2:
				case RANGE1_STARTS_BEFORE_RANGE2_ENDS_AFTER_RANGE2:
				case RANGE1_STARTS_BEFORE_RANGE2_ENDS_AT_RANGE2_END:
					// delete range covers range, don't save range, get next range
					range = rangeIt.hasNext() ? rangeIt.next() : null;
					break;
				case RANGE1_STARTS_AT_RANGE2_ENDS_BEFORE_RANGE2:
				case RANGE1_STARTS_BEFORE_RANGE2_ENDS_INSIDE_RANGE2:
					// delete range overlaps first part, adjust range and get next delete range
					range = new AddressRangeImpl(deleteRange.getMaxAddress().next(),
						range.getMaxAddress());
					deleteRange = deleteRangeIt.hasNext() ? deleteRangeIt.next() : null;
					break;
				case RANGE1_STARTS_INSIDE_RANGE2_ENDS_AFTER_RANGE2:
				case RANGE1_STARTS_INSIDE_RANGE2_ENDS_AT_RANGE2:
					// delete range truncates back of range, put in first part of range and get next range
					Address nextEnd = deleteRange.getMinAddress().previous();
					newSet.addRange(range.getMinAddress(), nextEnd);
					range = rangeIt.hasNext() ? rangeIt.next() : null;
					break;
				case RANGE1_STARTS_INSIDE_RANGE2_ENDS_INSIDE_RANGE2:
					// delete range is interior, save first part of range, adjust range and get
					// next delete range
					newSet.addRange(range.getMinAddress(), deleteRange.getMinAddress().previous());
					range = new AddressRangeImpl(deleteRange.getMaxAddress().next(),
						range.getMaxAddress());
					deleteRange = deleteRangeIt.hasNext() ? deleteRangeIt.next() : null;
					break;

			}
		}
		while (range != null) {
			newSet.add(range);
			range = rangeIt.hasNext() ? rangeIt.next() : null;
		}
		return newSet;
	}

	private AddressSet xorSets(AddressSetView addrSet) {
		AddressSet newSet = new AddressSet();

		AddressRangeIterator range1It = getAddressRanges();
		AddressRangeIterator range2It = addrSet.getAddressRanges();

		AddressRange range1 = range1It.hasNext() ? range1It.next() : null;
		AddressRange range2 = range2It.hasNext() ? range2It.next() : null;

		while (range1 != null && range2 != null) {
			switch (compareRange(range1, range2)) {
				case RANGE1_COMPLETELY_AFTER_RANGE2:
					// no overlap in range2, add it to tree and get next range2
					newSet.add(range2);
					range2 = range2It.hasNext() ? range2It.next() : null;
					break;
				case RANGE1_COMPLETELY_BEFORE_RANGE2:
					// no overlap in range1, add it to tree and get next range1
					newSet.add(range1);
					range1 = range1It.hasNext() ? range1It.next() : null;
					break;
				case RANGE1_EQUALS_RANGE2:
					// total overlap don't add either one, get next range1 and range2
					range1 = range1It.hasNext() ? range1It.next() : null;
					range2 = range2It.hasNext() ? range2It.next() : null;
					break;
				case RANGE1_STARTS_AT_RANGE2_ENDS_AFTER_RANGE2:
					// range2 overlaps, truncate range1 and get new range2
					range1 =
						new AddressRangeImpl(range2.getMaxAddress().next(), range1.getMaxAddress());
					range2 = range2It.hasNext() ? range2It.next() : null;
					break;
				case RANGE1_STARTS_AT_RANGE2_ENDS_BEFORE_RANGE2:
					// range1 overlaps, truncate range2 and get new range1
					range2 =
						new AddressRangeImpl(range1.getMaxAddress().next(), range2.getMaxAddress());
					range1 = range1It.hasNext() ? range1It.next() : null;
					break;
				case RANGE1_STARTS_BEFORE_RANGE2_ENDS_AFTER_RANGE2:
					// add beginning of range1 to tree, truncate range1 to end of range2, get new range2
					newSet.addRange(range1.getMinAddress(), range2.getMinAddress().previous());
					range1 =
						new AddressRangeImpl(range2.getMaxAddress().next(), range1.getMaxAddress());
					range2 = range2It.hasNext() ? range2It.next() : null;
					break;
				case RANGE1_STARTS_BEFORE_RANGE2_ENDS_AT_RANGE2_END:
					// add beginning of range1 to tree, get new range1 and range2
					newSet.addRange(range1.getMinAddress(), range2.getMinAddress().previous());
					range1 = range1It.hasNext() ? range1It.next() : null;
					range2 = range2It.hasNext() ? range2It.next() : null;
					break;
				case RANGE1_STARTS_BEFORE_RANGE2_ENDS_INSIDE_RANGE2:
					// add in beginning of range1 to tree, truncate range2 to end of range1, get new range1
					newSet.addRange(range1.getMinAddress(), range2.getMinAddress().previous());
					range2 =
						new AddressRangeImpl(range1.getMaxAddress().next(), range2.getMaxAddress());
					range1 = range1It.hasNext() ? range1It.next() : null;
					break;
				case RANGE1_STARTS_INSIDE_RANGE2_ENDS_AFTER_RANGE2:
					// add in beginning of range2, truncate range1 to end of range2, get new range2
					newSet.addRange(range2.getMinAddress(), range1.getMinAddress().previous());
					range1 =
						new AddressRangeImpl(range2.getMaxAddress().next(), range1.getMaxAddress());
					range2 = range2It.hasNext() ? range2It.next() : null;
					break;
				case RANGE1_STARTS_INSIDE_RANGE2_ENDS_AT_RANGE2:
					// add beginning of range2 to tree, get new range1 and range2
					newSet.addRange(range2.getMinAddress(), range1.getMinAddress().previous());
					range1 = range1It.hasNext() ? range1It.next() : null;
					range2 = range2It.hasNext() ? range2It.next() : null;
					break;
				case RANGE1_STARTS_INSIDE_RANGE2_ENDS_INSIDE_RANGE2:
					// add beginning of range2 to tree, truncate range2 to end range1, get new range1
					newSet.addRange(range2.getMinAddress(), range1.getMinAddress().previous());
					range2 =
						new AddressRangeImpl(range1.getMaxAddress().next(), range2.getMaxAddress());
					range1 = range1It.hasNext() ? range1It.next() : null;
					break;

			}
		}
		while (range1 != null) {
			newSet.add(range1);
			range1 = range1It.hasNext() ? range1It.next() : null;
		}
		while (range2 != null) {
			newSet.add(range2);
			range2 = range2It.hasNext() ? range2It.next() : null;
		}
		return newSet;
	}

	private AddressRange getRange(RedBlackEntry<Address, Address> entry) {
		return new AddressRangeImpl(entry.getKey(), entry.getValue());
	}

	private boolean contains(RedBlackEntry<Address, Address> entry, Address start) {
		return entry.getKey().compareTo(start) <= 0 && entry.getValue().compareTo(start) >= 0;
	}

	private AddressSet mergeSets(AddressSetView addrSet) {
		AddressSet newSet = new AddressSet();

		AddressRangeIterator thisIter = getAddressRanges();
		AddressRangeIterator thatIter = addrSet.getAddressRanges();

		AddressRange thisRange = (thisIter.hasNext() ? thisIter.next() : null);
		AddressRange thatRange = (thatIter.hasNext() ? thatIter.next() : null);

		while (thisRange != null && thatRange != null) {
			if (thisRange.getMinAddress().compareTo(thatRange.getMinAddress()) <= 0) {
				newSet.add(thisRange);
				thisRange = (thisIter.hasNext() ? thisIter.next() : null);
			}
			else {
				newSet.add(thatRange);
				thatRange = (thatIter.hasNext() ? thatIter.next() : null);
			}
		}
		while (thisRange != null) {
			newSet.add(thisRange);
			thisRange = (thisIter.hasNext() ? thisIter.next() : null);
		}
		while (thatRange != null) {
			newSet.add(thatRange);
			thatRange = (thatIter.hasNext() ? thatIter.next() : null);
		}
		return newSet;
	}

	private void consumeFollowOnNodes(RedBlackEntry<Address, Address> node) {
		Address rangeEnd = node.getValue();

		RedBlackEntry<Address, Address> nextNode = node.getSuccessor();

		while (nextNode != null) {
			Address nextStart = nextNode.getKey();
			if (rangeEnd.compareTo(nextStart) < 0 && !rangeEnd.isSuccessor(nextStart)) {
				return;
			}
			Address nextEnd = nextNode.getValue();
			if (nextEnd.compareTo(rangeEnd) > 0) {
				updateRangeEndAddress(node, nextEnd);
			}
			nextNode = deleteRangeNode(nextNode);
		}

	}

	private void checkValidRange(Address start, Address end) {
		if (start == null || end == null) {
			throw new IllegalArgumentException("Attempted to add a null address to this set.");
		}

		if (start.compareTo(end) > 0) {
			throw new IllegalArgumentException("Start address must be less than or equal to " +
				"end address:  Start " + start + "   end = " + end);
		}

		if (!start.getAddressSpace().equals(end.getAddressSpace())) {
			throw new IllegalArgumentException(
				"Start and end addresses must be in same address space!  Start " + start +
					"   end = " + end);
		}
	}

	private RedBlackEntry<Address, Address> createRangeNode(Address start, Address end) {
		RedBlackEntry<Address, Address> newEntry = rbTree.getOrCreateEntry(start);
		newEntry.setValue(end);
		addressCount += end.subtract(start) + 1;
		return newEntry;
	}

	private void updateRangeEndAddress(RedBlackEntry<Address, Address> entry, Address newEnd) {
		addressCount += newEnd.subtract(entry.getValue());
		entry.setValue(newEnd);
	}

	private RedBlackEntry<Address, Address> deleteRangeNode(RedBlackEntry<Address, Address> entry) {
		RedBlackEntry<Address, Address> successor = entry.getSuccessor();
		addressCount -= entry.getValue().subtract(entry.getKey()) + 1;
		rbTree.deleteEntry(entry);
		return successor;
	}

	private class AddressRangeIteratorAdapter implements AddressRangeIterator {

		private Iterator<RedBlackEntry<Address, Address>> iterator;

		public AddressRangeIteratorAdapter(Iterator<RedBlackEntry<Address, Address>> iterator) {
			this.iterator = iterator;
		}

		@Override
		public boolean hasNext() {
			return iterator.hasNext();
		}

		@Override
		public AddressRange next() {
			RedBlackEntry<Address, Address> next = iterator.next();
			return new AddressRangeImpl(next.getKey(), next.getValue());
		}

		@Override
		public void remove() {
			iterator.remove();
		}

		@Override
		public Iterator<AddressRange> iterator() {
			return this;
		}

	}

	private class MyAddressIterator implements AddressIterator {
		protected Address nextAddr = null;
		protected Address endAddr = null;
		protected final boolean forward;
		protected final ListIterator<RedBlackEntry<Address, Address>> it;

		private MyAddressIterator(Address start, boolean forward) {
			this.forward = forward;

			it = getIteratorContainingOrAfter(start);

			if (!it.hasNext()) {
				return;
			}

			RedBlackEntry<Address, Address> entry = it.next();
			if (start != null && contains(entry, start)) {
				nextAddr = start;
				endAddr = forward ? entry.getValue() : entry.getKey();
			}
			else {
				nextAddr = forward ? entry.getKey() : entry.getValue();
				endAddr = forward ? entry.getValue() : entry.getKey();
			}
		}

		private ListIterator<RedBlackEntry<Address, Address>> getIteratorContainingOrAfter(
				Address start) {

			if (start == null) {
				return rbTree.iterator(forward);
			}

			// if going backwards, the first entry from the iterator will either contain the start
			// or be the first range we want beyond the start.
			if (!forward) {
				return rbTree.iterator(start, false);
			}

			// going forward is a bit trickier, the start may be in the previous range
			ListIterator<RedBlackEntry<Address, Address>> iterator = rbTree.iterator(start, true);
			if (iterator.hasPrevious()) {
				RedBlackEntry<Address, Address> entry = iterator.previous();
				if (!contains(entry, start)) {
					// if start is not in this previous range, advance the iterator
					iterator.next();
				}
			}
			return iterator;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean hasNext() {
			return nextAddr != null;
		}

		@Override
		public Address next() {
			if (nextAddr != null) {
				Address addr = nextAddr;
				findNext();
				return addr;
			}
			return null;
		}

		@Override
		public Iterator<Address> iterator() {
			return this;
		}

		protected void findNext() {
			if (nextAddr.equals(endAddr)) {
				if (it.hasNext()) {
					RedBlackEntry<Address, Address> entry = it.next();
					nextAddr = forward ? entry.getKey() : entry.getValue();
					endAddr = forward ? entry.getValue() : entry.getKey();
					return;
				}
				nextAddr = null;
			}
			else {
				nextAddr = forward ? nextAddr.next() : nextAddr.previous();
			}
		}
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView set) {
		if (set.getNumAddressRanges() > getNumAddressRanges()) {
			return set.findFirstAddressInCommon(this);
		}
		for (AddressRange addressRange : set) {
			Address start = addressRange.getMinAddress();
			Address end = addressRange.getMaxAddress();
			AddressIterator it = getAddresses(start, true);
			if (!it.hasNext()) {
				break; // end of this this set reached, so not possible match.
			}
			Address addr = it.next();
			if (addr.compareTo(end) <= 0) {
				return addr; // its in the range, so we found it!
			}
		}
		return null;
	}

	/**
	 * Delete all addresses from the minimum address in the set up to and including toAddr.
	 * Addresses less-than-or-equal to specified 
	 * address based upon {@link Address} comparison.
	 * 
	 * @param toAddr only addresses greater than toAddr will be left in the set.
	 */
	public void deleteFromMin(Address toAddr) {
		if (isEmpty()) {
			return;
		}
		// check if toAddr is already before the start of the set
		if (toAddr.compareTo(getMinAddress()) < 0) {
			return;
		}
		delete(getMinAddress(), toAddr);
	}

	/**
	 * Delete all addresses starting at the fromAddr to the maximum address in the set.
	 * Addresses greater-than-or-equal to specified 
	 * address based upon {@link Address} comparison.
	 * 
	 * @param fromAddr only addresses less than fromAddr will be left in the set.
	 */
	public void deleteToMax(Address fromAddr) {
		if (isEmpty()) {
			return;
		}

		// check if endAddr is already past the end of the set
		if (fromAddr.compareTo(getMaxAddress()) > 0) {
			return;
		}
		delete(fromAddr, getMaxAddress());
	}
}
