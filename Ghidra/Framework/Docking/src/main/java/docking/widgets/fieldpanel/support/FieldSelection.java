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
package docking.widgets.fieldpanel.support;

import ghidra.framework.options.SaveState;
import ghidra.util.Msg;

import java.math.BigInteger;
import java.util.*;

import org.jdom.Element;

/**
 * Interface for reporting the FieldViewer selection.  The selection consists of
 * a sequence of ranges of indexes.
 */
public class FieldSelection implements Iterable<FieldRange> {

	private List<FieldRange> ranges;

	/**
	 * Construct a new empty FieldSelection.
	 */
	public FieldSelection() {
		ranges = new ArrayList<FieldRange>(4);
	}

	/**
	 * Construct a new FieldSelection with the same selection as the given FieldSelection.
	 * @param selection the FieldSelection to copy.
	 */
	public FieldSelection(FieldSelection selection) {
		ranges = new ArrayList<FieldRange>(selection.ranges.size());
		for (FieldRange range : selection.ranges) {
			ranges.add(new FieldRange(range));
		}
	}

	/**
	 * Removes all indexes from the list.
	 */
	public void clear() {
		ranges = new ArrayList<FieldRange>(4);
	}

	/**
	 * Returns true if the given Field at the given index is in the selection.
	 * @param loc the field location.
	 * @return true if the field selection contains the specified location.
	 */
	public boolean contains(FieldLocation loc) {
		return getRangeContaining(loc) != null;
	}

	/**
	 * Returns the range if the given Field at the given index is in the selection.
	 * Otherwise returns null.
	 * @param loc location to find the range for.
	 */
	public FieldRange getRangeContaining(FieldLocation loc) {
		int insertIndex = Collections.binarySearch(ranges, new FieldRange(loc, FieldLocation.MAX));

		// exact match
		if (insertIndex >= 0) {
			return ranges.get(insertIndex);
		}

		// examine range before insert index to see if we are inside it
		int compareIndex = -insertIndex - 2;

		if (compareIndex < 0) {
			return null;
		}

		FieldRange compareRange = ranges.get(compareIndex);

		if (compareRange.contains(loc)) {
			return compareRange;
		}
		return null;
	}

	/**
	 * Returns true if the all the fields in the layout with the given index are
	 *  included in this selection.
	 * @param index index of the layout to test.

	 */
	public boolean containsEntirely(BigInteger index) {
		FieldLocation start = new FieldLocation(index, 0, 0, 0);
		FieldLocation end = new FieldLocation(index.add(BigInteger.ONE), 0, 0, 0);
		return containsEntirely(new FieldRange(start, end));
	}

	public boolean containsEntirely(FieldRange range) {
		FieldRange rangeContaining = getRangeContaining(range.start);
		if (rangeContaining == null) {
			return false;
		}
		return range.end.compareTo(rangeContaining.end) <= 0;
	}

	public boolean excludesEntirely(FieldRange range) {
		int searchIndex = Collections.binarySearch(ranges, range);
		if (searchIndex >= 0) {
			return false;
		}
		searchIndex = -searchIndex - 2;
		if (searchIndex >= 0) {
			if (ranges.get(searchIndex).intersects(range)) {
				return false;
			}
		}
		searchIndex++;
		if (searchIndex < ranges.size()) {
			return !ranges.get(searchIndex).intersects(range);
		}
		return true;
	}

	public boolean excludesEntirely(BigInteger index) {
		FieldLocation start = new FieldLocation(index, 0, 0, 0);
		FieldLocation end = new FieldLocation(index.add(BigInteger.ONE), 0, 0, 0);
		return excludesEntirely(new FieldRange(start, end));
	}

	/**
	 * Adds a field range to this selection.
	 * @param start the starting field location.
	 * @param end the ending field location.
	 */
	public void addRange(FieldLocation start, FieldLocation end) {
		if (start.equals(end)) {
			return;
		}

		FieldRange newRange = new FieldRange(start, end);
		int insertIndex = Collections.binarySearch(ranges, newRange);
		if (insertIndex >= 0) {
			return; // already contains range
		}

		insertIndex = -insertIndex - 2;

		if (insertIndex >= 0 && ranges.get(insertIndex).canMerge(newRange)) {
			ranges.get(insertIndex).merge(newRange);
		}
		else {
			insertIndex++;
			ranges.add(insertIndex, newRange);
		}

		FieldRange currentRange = ranges.get(insertIndex);
		int checkIndex = insertIndex + 1;
		while (checkIndex < ranges.size()) {
			if (!currentRange.canMerge(ranges.get(checkIndex))) {
				break;
			}
			currentRange.merge(ranges.get(checkIndex));
			ranges.remove(checkIndex);
		}
	}

	/**
	 * Add the all the indexes from startIndex to endIndex to the selection.  The added
	 * range includes the startIndex, but not the endIndex.
	 * @param startIndex the start index of the layouts to include
	 * @param endIndex the end index(not inclusive) of the layouts to include
	 */
	public void addRange(int startIndex, int endIndex) {
		addRange(new FieldLocation(startIndex, 0, 0, 0), new FieldLocation(endIndex, 0, 0, 0));
	}

	public void addRange(BigInteger startIndex, BigInteger endIndex) {
		addRange(new FieldLocation(startIndex, 0, 0, 0), new FieldLocation(endIndex, 0, 0, 0));
	}

	public void addRange(int startIndex, int startFieldNum, int endIndex, int endFieldNum) {
		addRange(new FieldLocation(startIndex, startFieldNum, 0, 0), new FieldLocation(endIndex,
			endFieldNum, 0, 0));
	}

	public void addRange(BigInteger startIndex, int startFieldNum, BigInteger endIndex,
			int endFieldNum) {
		addRange(new FieldLocation(startIndex, startFieldNum, 0, 0), new FieldLocation(endIndex,
			endFieldNum, 0, 0));
	}

	/**
	 * Removes the given field range from the current selection.
	 * @param start the starting field location.
	 * @param end the ending field location.
	 */
	public void removeRange(FieldLocation start, FieldLocation end) {
		FieldRange deleteRange = new FieldRange(start, end);
		int insertIndex = Collections.binarySearch(ranges, deleteRange);

		// if exact match, remove it
		if (insertIndex >= 0) {
			ranges.remove(insertIndex);
			return;
		}

		insertIndex = -insertIndex - 2;
		if (insertIndex >= 0) {
			FieldRange range = ranges.get(insertIndex);
			if (deleteRange.intersects(range)) {
				FieldRange leftOver = range.subtract(deleteRange);
				if (range.isEmpty()) {
					ranges.remove(insertIndex);
					insertIndex--;
				}
				else if (leftOver != null) {
					ranges.add(insertIndex + 1, leftOver);
					return;
				}
			}
		}
		insertIndex++;
		while (insertIndex < ranges.size()) {
			FieldRange range = ranges.get(insertIndex);
			if (!deleteRange.intersects(range)) {
				return;
			}
			FieldRange leftOver = range.subtract(deleteRange);
			if (range.isEmpty()) {
				ranges.remove(insertIndex);
			}
			else if (leftOver != null) {
				ranges.add(insertIndex + 1, leftOver);
				return;
			}
			else {
				return;
			}
		}
	}

	/**
	 * Removes the all the fields in the index range from the selection.
	 * @param startIndex the first index in the range to remove.
	 * @param endIndex the last index in the range to remove.
	 */
	public void removeRange(int startIndex, int endIndex) {
		removeRange(new FieldLocation(startIndex, 0, 0, 0), new FieldLocation(endIndex, 0, 0, 0));
	}

	public void removeRange(BigInteger startIndex, BigInteger endIndex) {
		removeRange(new FieldLocation(startIndex, 0, 0, 0), new FieldLocation(endIndex, 0, 0, 0));
	}

	/**
	 * Returns the current number of ranges in the list.
	 */
	public int getNumRanges() {
		return ranges.size();
	}

	/**
	 * Returns the i'th Field Range in the selection.
	 * @param rangeNum the index of the range to retrieve.
	 */
	public FieldRange getFieldRange(int rangeNum) {
		return ranges.get(rangeNum);
	}

	/**
	* Compute the intersection of this field selection and another one.
	* The intersection of two field selections is all fields existing in 
	* both selections.
	* <P>Note: This field selection becomes the intersection.
	*
	* @param selection field selection to intersect.
	*/
	public final void intersect(FieldSelection selection) {
		if (selection == null || this.ranges.size() == 0 || selection.ranges.size() == 0) {
			clear();
			return;
		}

		// C = A - B
		// return A - C
		FieldSelection A = this;
		FieldSelection B = selection;
		FieldSelection C = new FieldSelection(this);

		C.delete(B);
		A.delete(C);
	}

	/**
	 * Computes the intersection of this field selection and the given field selection.
	 * @param selection the selection to intersect with.
	 */
	public final FieldSelection findIntersection(FieldSelection selection) {
		if (selection == null || this.ranges.size() == 0 || selection.ranges.size() == 0) {
			return new FieldSelection();
		}

		// C = A - B
		// return A - C
		FieldSelection A = new FieldSelection(this);
		FieldSelection B = selection;
		FieldSelection C = new FieldSelection(this);

		C.delete(B);
		A.delete(C);
		return A;
	}

	/**
	 * Delete all fields in the ranges in the given field selection from this one.
	 * @param selection the field selection fields to remove from this 
	 * field selection.
	 */
	public final void delete(FieldSelection selection) {
		if (selection == null || this.ranges.size() == 0 || selection.ranges.size() == 0) {
			return;
		}

		// process all ranges in the selection, delete each one's
		// associated fields from this set.
		for (FieldRange range : selection.ranges) {
			removeRange(range.start, range.end);
		}
	}

	/**
	 * Insert all fields in the ranges in the given field selection from this one.
	 * @param selection the field selection fields to add to this 
	 * field selection.
	 */
	public final void insert(FieldSelection selection) {
		if (selection == null || selection.getNumRanges() == 0) {
			return;
		}

		// process all ranges in the selection, add each one's
		// associated fields from this set.
		for (FieldRange range : selection.ranges) {
			addRange(range.start, range.end);
		}
	}

	/**
	 * Prints out the ranges for debugging.
	 */
	public void printRanges() {
		Msg.debug(this, "*********");
		for (FieldRange range : ranges) {
			Msg.debug(this, range);
		}
		Msg.debug(this, "**********");
	}

	@Override
	public String toString() {
		StringBuffer buf = new StringBuffer();
		for (FieldRange range : ranges) {
			buf.append(range.toString());
		}
		return buf.toString();
	}

	/**
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof FieldSelection)) {
			return false;
		}
		FieldSelection other = (FieldSelection) obj;
		if (ranges.size() != other.ranges.size()) {
			return false;
		}
		int n = ranges.size();
		for (int i = 0; i < n; i++) {
			FieldRange thisRange = ranges.get(i);
			FieldRange otherRange = other.ranges.get(i);
			if (!thisRange.equals(otherRange)) {
				return false;
			}
		}
		return true;
	}

	public void save(SaveState saveState) {
		if (ranges.isEmpty()) {
			return;
		}
		Element listElement = new Element("FIELD_RANGES");
		for (FieldRange range : ranges) {
			Element element = range.getElement();
			listElement.addContent(element);
		}
		saveState.putXmlElement("FIELD_SELECTION", listElement);
	}

	public void load(SaveState saveState) {
		clear();
		Element element = saveState.getXmlElement("FIELD_SELECTION");
		if (element != null) {
			List<?> children = element.getChildren();
			for (Object object : children) {
				Element child = (Element) object;
				ranges.add(new FieldRange(child));
			}
		}
	}

	public boolean isEmpty() {
		return ranges.size() == 0;
	}

	public FieldSelection intersect(int index) {
		FieldLocation start = new FieldLocation(index);
		FieldLocation end = new FieldLocation(index + 1);

		FieldRange range = new FieldRange(start, end);
		return intersect(range);
	}

	public FieldSelection intersect(BigInteger index) {
		FieldLocation start = new FieldLocation(index);
		FieldLocation end = new FieldLocation(index.add(BigInteger.ONE));

		FieldRange range = new FieldRange(start, end);
		return intersect(range);
	}

	public FieldSelection intersect(FieldRange range) {
		FieldSelection intersection = new FieldSelection();

		int insertIndex = Collections.binarySearch(ranges, range);

		// if exact match, return it;
		if (insertIndex >= 0) {
			intersection.addRange(range);
			return intersection;
		}
		insertIndex = -insertIndex - 2;
		if (insertIndex < 0) {
			insertIndex++;
		}
		while (insertIndex < ranges.size()) {
			FieldRange searchRange = ranges.get(insertIndex);
			if (searchRange.start.compareTo(range.end) >= 0) {
				break;
			}
			FieldRange newRange = searchRange.intersect(range);
			if (newRange != null) {
				intersection.addRange(newRange);
			}
			insertIndex++;
		}

		return intersection;
	}

	public void addRange(FieldRange range) {
		addRange(range.start, range.end);
	}

	@Override
	public Iterator<FieldRange> iterator() {
		return ranges.iterator();
	}
}
