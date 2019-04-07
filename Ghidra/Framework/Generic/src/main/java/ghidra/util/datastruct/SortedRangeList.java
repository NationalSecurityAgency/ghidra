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

/**
 * Provides a list of integer ranges that are maintained in sorted order. 
 * When a range is added any ranges that overlap or are adjacent to one another 
 * will coalesce into a single range.
 */
public class SortedRangeList implements Iterable<Range> {
	TreeSet<Range> set;

	/**
	 * Creates a new empty sorted range list.
	 */
	public SortedRangeList() {
		set = new TreeSet<Range>();
	}

	/**
	 * Creates a new sorted range list with ranges equivalent to those in the 
	 * specified list.
	 * @param list the sorted range list to make an equivalent copy of.
	 */
	public SortedRangeList(SortedRangeList list) {
		set = new TreeSet<Range>();
		Iterator<Range> it = list.set.iterator();
		while (it.hasNext()) {
			Range r = it.next();
			addRange(r.min, r.max);
		}
	}

	/**
	 * Adds the range from min to max to this sorted range list.
	 * If the range is adjacent to or overlaps any other existing ranges,
	 * then those ranges will coalesce.
	 * @param min the range minimum
	 * @param max the range maximum (inclusive)
	 */
	public void addRange(int min, int max) {
		Range key = new Range(min, min);
		SortedSet<Range> headSet = set.headSet(key);
		if (!headSet.isEmpty()) {
			Range last = headSet.last();
			if (min <= last.max + 1) {
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
		if (max < first.min - 1) {
			set.add(new Range(min, max));
			return;
		}
		first.min = Math.min(first.min, min);
		first.max = Math.max(first.max, max);
		coalesce(first, it);
	}

	/**
	 * Returns an iterator over all the ranges in this list.
	 */
	public Iterator<Range> getRanges() {
		return set.iterator();
	}

	/**
	 * Returns an iterator over all the ranges in this list that iterates in the direction specified.
	 * @param forward true indicates to iterate forward from minimum to maximum range. 
	 * false indicates backward iteration form maximum to minimum.
	 */
	public Iterator<Range> getRanges(boolean forward) {
		if (forward) {
			return set.iterator();
		}
		Iterator<Range> it = set.iterator();
		LinkedList<Range> ll = new LinkedList<Range>();
		while (it.hasNext()) {
			ll.addFirst(it.next());
		}
		return ll.iterator();
	}

	/**
	 * Returns the minimum int value in this sorted range list.
	 * @throws NoSuchElementException if the list is empty.
	 */
	public int getMin() throws NoSuchElementException {
		Range r = set.first();
		return r.min;
	}

	/**
	 * Returns the maximum int value in this sorted range list.
	 * @throws NoSuchElementException if the list is empty.
	 */
	public int getMax() throws NoSuchElementException {
		Range r = set.last();
		return r.max;
	}

	/**
	 * Returns the number of ranges in the list.
	 */
	public int getNumRanges() {
		return set.size();
	}

	/**
	 * Removes the indicated range of values from the list. This will remove 
	 * any ranges or portion of ranges that overlap the indicated range.
	 * @param min the minimum value for the range to remove.
	 * @param max the maximum value for the range to remove.
	 */
	public void removeRange(int min, int max) {
		Range key = new Range(min, min);
		SortedSet<Range> headSet = set.headSet(key);
		if (!headSet.isEmpty()) {
			Range last = headSet.last();
			if (last.max >= min) {
				if (max < last.max) {
					set.add(new Range(max + 1, last.max));
					last.max = Math.min(last.max, min - 1);
					return;
				}
				last.max = Math.min(last.max, min - 1);
			}
		}
		Iterator<Range> it = set.tailSet(key).iterator();
		while (it.hasNext()) {
			Range next = it.next();
			if (next.min > max) {
				break;
			}
			else if (next.max > max) {
				next.min = max + 1;
				break;
			}
			it.remove();
		}
	}

	/**
	 * Coalesces any ranges that are adjacent to or overlap the indicated range.
	 * @param range the range to check for coalescing.
	 * @param it the iterator to use for coalescing.
	 */
	void coalesce(Range range, Iterator<Range> it) {
		while (it.hasNext()) {
			Range next = it.next();
			if (next.min > range.max + 1) {
				break;
			}
			range.max = Math.max(range.max, next.max);
			it.remove();
		}
	}

	/**
	 * Returns true if the value is contained in any ranges within this list.
	 * @param value the value to check for.
	 */
	public boolean contains(int value) {
		Range key = new Range(value, value);
		SortedSet<Range> head = set.headSet(key);
		if (!head.isEmpty()) {
			if (head.last().max >= value) {
				return true;
			}
		}
		return set.contains(key);
	}

	private Range getRangeContaining(int value) {
		Range key = new Range(value, value);
		SortedSet<Range> head = set.headSet(key);
		if (!head.isEmpty()) {
			Range last = head.last();
			if (last.max >= value) {
				return last;
			}
		}
		SortedSet<Range> tail = set.tailSet(key);
		if (!tail.isEmpty()) {
			Range range = tail.first();
			if (range.min == value) {
				return range;
			}
		}
		return null;
	}

	/**
	 * Returns true if a single range contains all the values from min to max.
	 * @param min the minimum value
	 * @param max the maximum value
	 */
	public boolean contains(int min, int max) {
		Range range = getRangeContaining(min);
		if (range != null) {
			return range.contains(max);
		}
		return false;
	}

	/**
	 * Gets the range index for the range containing the specified value.
	 * @param value the value to look for.
	 * @return the range index or a negative value if the range list doesn't contain the value.
	 */
	public int getRangeIndex(int value) {
		Range key = new Range(value, value);
		SortedSet<Range> head = set.headSet(key);
		int index = head.size() - 1;
		if (!head.isEmpty()) {
			Range last = head.last();
			if (last.max >= value) {
				return index;
			}
		}
		index++;
		SortedSet<Range> tail = set.tailSet(key);
		if (!tail.isEmpty()) {
			Range range = tail.first();
			if (range.min == value) {
				return index;
			}
		}
		return -index - 1;
	}

	/**
	 * Gets the nth range in this list as indicated by the value of index.
	 * @param index value indicating which nth range to get.
	 * @return the range or null if there is no such range in this list.
	 */
	public Range getRange(int index) {
		Iterator<Range> it = set.iterator();
		while (index > 0 && it.hasNext()) {
			it.next();
			index--;
		}
		if (index == 0 && it.hasNext()) {
			return it.next();
		}
		return null;
	}

	/**
	 * Gets the total number of int values in this range.
	 * @return the number of int values.
	 */
	public long getNumValues() {
		Iterator<Range> it = set.iterator();
		long n = 0;
		while (it.hasNext()) {
			Range r = it.next();
			n += r.size();
		}
		return n;
	}

	/**
	 * Returns true if the range from min to max intersects (overlaps) any ranges in this sorted range list.
	 * @param min the range minimum value.
	 * @param max the range maximum value
	 */
	public boolean intersects(int min, int max) {
		Range key = new Range(min, min);
		SortedSet<Range> head = set.headSet(key);
		if (!head.isEmpty()) {
			Range last = head.last();
			if (last.max >= min) {
				return true;
			}
		}
		SortedSet<Range> tail = set.tailSet(key);
		if (!tail.isEmpty()) {
			Range next = tail.first();
			if (next.min <= max) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns true if the range list is empty.
	 */
	public boolean isEmpty() {
		return set.isEmpty();
	}

	/**
	 * Removes all the ranges that are in the specified other list from this list.
	 * @param other the other sorted range list.
	 */
	public void remove(SortedRangeList other) {
		Iterator<Range> it = other.getRanges();
		while (it.hasNext()) {
			Range r = it.next();
			removeRange(r.min, r.max);
		}
	}

	/**
	 * Creates a new SortedRangeList that is the intersection of this range list and the other range list specified.
	 * @param other the other range list
	 * @return the new SortedRangeList representing the intersection.
	 */
	public SortedRangeList intersect(SortedRangeList other) {
		SortedRangeList srl = new SortedRangeList(this);
		srl.remove(other);
		SortedRangeList srl2 = new SortedRangeList(this);
		srl2.remove(srl);
		return srl2;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		StringBuffer buf = new StringBuffer();
		Iterator<Range> it = getRanges();
		if (it.hasNext()) {
			Range r = it.next();
			buf.append("[" + r.min + "," + r.max + "]");
		}
		while (it.hasNext()) {
			Range r = it.next();
			buf.append(" [" + r.min + "," + r.max + "]");
		}
		return buf.toString();
	}

	@Override
	public Iterator<Range> iterator() {
		return getRanges(true);
	}
}
