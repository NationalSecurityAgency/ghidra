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
package ghidra.app.merge.listing;

import ghidra.util.datastruct.*;

import java.util.Iterator;

class OffsetRanges {
	IntObjectHashtable<SortedRangeList> firstUseRanges;

	OffsetRanges() {
		firstUseRanges = new IntObjectHashtable<SortedRangeList>();
	}

	/**
	 * @param firstUse
	 * @param commonSrl
	 */
	public void addRangeList(int firstUse, SortedRangeList commonSrl) {
		SortedRangeList srl = firstUseRanges.get(firstUse);
		if (srl == null) {
			srl = new SortedRangeList();
			firstUseRanges.put(firstUse, srl);
		}
		Iterator<Range> iter = commonSrl.getRanges();
		while (iter.hasNext()) {
			Range range = iter.next();
			srl.addRange(range.min, range.max);
		}
	}

	void addRange(int firstUse, int min, int max) {
		SortedRangeList srl = firstUseRanges.get(firstUse);
		if (srl == null) {
			srl = new SortedRangeList();
			firstUseRanges.put(firstUse, srl);
		}
		srl.addRange(min, max);
	}

	boolean contains(int firstUse, int value) {
		SortedRangeList srl = firstUseRanges.get(firstUse);
		return (srl != null) ? srl.contains(value) : false;
	}

	@Override
	public String toString() {
		StringBuffer buf = new StringBuffer();
		int[] keys = firstUseRanges.getKeys();
		for (int i = 0; i < keys.length; i++) {
			int firstUse = keys[i];
			SortedRangeList srl = firstUseRanges.get(firstUse);
			buf.append("FirstUse=" + firstUse + " Offsets = " + srl + "\n");
		}
		return buf.toString();
	}

	OffsetRanges intersect(OffsetRanges otherChangeRanges) {
		OffsetRanges ranges = new OffsetRanges();
		int[] keys = firstUseRanges.getKeys();
		for (int firstUseOffset : keys) {
			SortedRangeList firstUseList = firstUseRanges.get(firstUseOffset);
			SortedRangeList otherList = otherChangeRanges.firstUseRanges.get(firstUseOffset);
			if (otherList != null) {
				SortedRangeList intersectedList = firstUseList.intersect(otherList);
				if (!intersectedList.isEmpty()) {
					ranges.addRangeList(firstUseOffset, intersectedList);
				}
			}
		}
		return ranges;
	}

	OffsetRanges union(OffsetRanges otherChangeRanges) {
		OffsetRanges ranges = new OffsetRanges();
		int[] keys = firstUseRanges.getKeys();
		int[] otherKeys = otherChangeRanges.firstUseRanges.getKeys();
		for (int firstUseOffset : keys) {
			SortedRangeList firstUseList = firstUseRanges.get(firstUseOffset);
			SortedRangeList otherList = otherChangeRanges.firstUseRanges.get(firstUseOffset);
			SortedRangeList combinedList = new SortedRangeList();
			Iterator<Range> it = firstUseList.getRanges();
			while (it.hasNext()) {
				Range r = it.next();
				combinedList.addRange(r.min, r.max);
			}
			if (otherList != null) {
				it = otherList.getRanges();
				while (it.hasNext()) {
					Range r = it.next();
					combinedList.addRange(r.min, r.max);
				}
			}
			ranges.addRangeList(firstUseOffset, combinedList);
		}
		for (int firstUseOffset : otherKeys) {
			if (ranges.firstUseRanges.contains(firstUseOffset)) {
				continue;
			}
			SortedRangeList firstUseList = firstUseRanges.get(firstUseOffset);
			SortedRangeList otherList = otherChangeRanges.firstUseRanges.get(firstUseOffset);
			SortedRangeList combinedList = new SortedRangeList();
			Iterator<Range> it = otherList.getRanges();
			while (it.hasNext()) {
				Range r = it.next();
				combinedList.addRange(r.min, r.max);
			}
			if (firstUseList != null) {
				it = firstUseList.getRanges();
				while (it.hasNext()) {
					Range r = it.next();
					combinedList.addRange(r.min, r.max);
				}
			}
			ranges.addRangeList(firstUseOffset, combinedList);
		}
		return ranges;
	}
}
