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
package ghidra.util.datastruct;

import java.util.*;
import java.util.Iterator;
import java.util.SortedSet;

/**
 * Provides a list of integer ranges that are maintained in sorted order where
 * adjacent ranges do not coalesce. 
 * When a range is added any ranges that overlap will coalesce into a single range.
 * However, ranges which are adjacent to one another will not coalesce.
 * This list maintains separate ranges which can have one range ending and 
 * the next range beginning at the next available integer value.
 */
public class AdjacentSortedRangeList extends SortedRangeList {

	/**
	 * Creates a new empty sorted range list which allows adjacent ranges.
	 */
	public AdjacentSortedRangeList() {
		super();
	}
	
	/**
	 * Creates a new adjacent sorted range list with ranges equivalent to those in the 
	 * specified list.
	 * @param list the adjacent sorted range list to make an equivalent copy of.
	 */
	public AdjacentSortedRangeList(AdjacentSortedRangeList list) {
		set = new TreeSet<Range>();
		Iterator<Range> it = list.set.iterator();
		while(it.hasNext()) {
			Range r = it.next();
			addRange(r.min, r.max);
		}
	}
	
	/**
	 * Adds the range from min to max to this adjacent sorted range list.
	 * If the range overlaps any other existing ranges, then those ranges will coalesce.
	 * If the range is adjacent to other
	 * @param min the range minimum
	 * @param max the range maximum (inclusive)
	 */
	@Override
    public void addRange(int min, int max) {
		Range key = new Range(min, min);
		SortedSet<Range> headSet = set.headSet(key);
		if (!headSet.isEmpty()) {
			Range last = headSet.last();
			if (min <= last.max){
				last.max = Math.max(last.max, max);
				coalesce(last, set.tailSet(key).iterator());
				return;
			}
		}
		SortedSet<Range> ss = set.tailSet(key);
		if (ss.isEmpty()) {
			set.add(new Range(min, max));
			return;
		}
		Iterator<Range> it = ss.iterator();
		Range first = it.next();
		if (max < first.min) {
			set.add(new Range(min, max));
			return;
		}
		first.min = Math.min(first.min, min);
		first.max = Math.max(first.max, max);
		coalesce(first, it);
	}
	
	/**
	 * Creates a new AdjacentSortedRangeList that is the intersection of this 
	 * range list and the other range list specified. The ranges in the new list will
	 * have breaks between adjacent ranges wherever either this range list
	 * or the other range list have breaks between adjacent ranges.
	 * @param other the other adjacent sorted range list
	 * @return the new AdjacentSortedRangeList representing the intersection.
	 */
	public AdjacentSortedRangeList intersect(AdjacentSortedRangeList other) {
		AdjacentSortedRangeList srl = new AdjacentSortedRangeList(this);
		srl.remove(other);
		AdjacentSortedRangeList srl2 = new AdjacentSortedRangeList(this);
		srl2.remove(srl);
		// Split ranges where other list's breaks are between adjacent ranges.
		int num = other.getNumRanges();
		for(int otherIndex=0; otherIndex < num-1; otherIndex++) {
			Range r = other.getRange(otherIndex);
			Range rNext = other.getRange(otherIndex+1);
			if (r.max+1 == rNext.min) {
				// Adjacent
				int myIndex = srl2.getRangeIndex(r.max);
				if (myIndex < 0) {
					continue;
				}
				Range myRange = srl2.getRange(myIndex);
				int min = myRange.min;
				int max = myRange.max;
				if (max >= rNext.min) {
					// split the range
					srl2.removeRange(min, max);
					srl2.addRange(min, r.max);
					srl2.addRange(rNext.min, max);
				}
			}
		}
		return srl2;
	}
}
