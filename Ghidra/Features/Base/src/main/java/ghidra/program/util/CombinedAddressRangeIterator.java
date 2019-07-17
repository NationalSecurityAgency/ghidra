/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.program.model.address.*;

import java.util.Iterator;

public class CombinedAddressRangeIterator implements AddressRangeIterator {
	AddressRangeManager manager1;
	AddressRangeManager manager2;

	public CombinedAddressRangeIterator(AddressRangeIterator it1, AddressRangeIterator it2) {
		manager1 = new AddressRangeManager(it1);
		manager2 = new AddressRangeManager(it2);
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return this;
	}

	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasNext() {
		return manager1.hasMoreRanges() || manager2.hasMoreRanges();
	}

	@Override
	public AddressRange next() {
		if (!manager1.hasMoreRanges()) {
			return manager2.getNextRange();
		}
		if (!manager2.hasMoreRanges()) {
			return manager1.getNextRange();
		}

		int minCompare = manager1.compareMin(manager2);
		if (minCompare == 0) {		// ranges have same start address
			return adjustEndRange();
		}
		if (minCompare > 0) {		// first range starts after second range
			return manager2.severMyHeadRange(manager1);
		}
		return manager1.severMyHeadRange(manager2);
	}

	private AddressRange adjustEndRange() {
		int maxCompare = manager1.compareMax(manager2);
		if (maxCompare == 0) {	// the two ranges are identical
			manager1.getNextRange();
			return manager2.getNextRange();
		}
		else if (maxCompare > 0) {  // second range ends before first range
			return manager1.severMyHeadAndAdvanceOtherManager(manager2);
		}
		else {						// first range ends before second range
			return manager2.severMyHeadAndAdvanceOtherManager(manager1);
		}
	}

	private class AddressRangeManager {
		AddressRangeIterator it;
		AddressRangeImpl range;

		AddressRangeManager(AddressRangeIterator it) {
			this.it = it;
			getNextRange();
		}

		/**
		 * Sets this manager's begin range to be the start range of the given manager.  This method
		 * will return the range that exists before the begin range is adjusted.
		 * @param manager The manager whose range will be used to set this manager's begin range.
		 * @return The range that is the difference between this manager's original and new begin
		 *         range.
		 */
		public AddressRange severMyHeadRange(AddressRangeManager manager) {
			if (range.getMaxAddress().compareTo(manager.range.getMinAddress()) < 0) {
				return getNextRange();
			}

			AddressRange severedRange =
				new AddressRangeImpl(range.getMinAddress(),
					manager.range.getMinAddress().previous());
			range = new AddressRangeImpl(manager.range.getMinAddress(), range.getMaxAddress());
			return severedRange;
		}

		/**
		 * Makes this manager's begin range equal to that of the given manager's end range plus
		 * one so that this manager's next range is after the current range. The given manager's
		 * range is advanced to its next range. This method returns
		 * the current range shared by both managers before truncation. 
		 * @param manager The manager whose end range this manager will use for its beginning range. 
		 * @return The current range shared by the two managers.
		 */
		public AddressRange severMyHeadAndAdvanceOtherManager(AddressRangeManager manager) {
			Address newMin = manager.range.getMaxAddress().next();
			range = new AddressRangeImpl(newMin, range.getMaxAddress());
			return manager.getNextRange();
		}

		public int compareMin(AddressRangeManager mgr) {
			return range.getMinAddress().compareTo(mgr.range.getMinAddress());
		}

		public int compareMax(AddressRangeManager mgr) {
			return range.getMaxAddress().compareTo(mgr.range.getMaxAddress());
		}

		public AddressRange getNextRange() {
			AddressRange tmpRange = range;
			range = it.hasNext() ? new AddressRangeImpl(it.next()) : null;
			return tmpRange;
		}

		public boolean hasMoreRanges() {
			return range != null;
		}

	}

}
