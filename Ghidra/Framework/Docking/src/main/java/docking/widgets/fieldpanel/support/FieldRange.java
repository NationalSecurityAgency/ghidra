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

import ghidra.util.exception.AssertException;

import java.math.BigInteger;

import org.jdom.Element;

/**
 *  Class to a range consisting of a start position within a start row to an end position within an 
 *  end row (exclusive).  
 *  <p>
 *  Conceptually, this class can be thought of as a range of rows (defined by 
 *  <code>startIndex</code> and <code>endindex</code>) with sub-positions within those rows (defined by
 *  <code>startField</code> and <code>endField</code>). As an example, consider a text select that begins on
 *  some word in a row and ends on another word in a different row.  
 */
public class FieldRange implements Comparable<FieldRange> {
	FieldLocation start;
	FieldLocation end;

	public FieldRange(FieldLocation start, FieldLocation end) {
		// if the parameters are backwards, fix it.
		if (start.compareTo(end) > 0) {
			this.start = new FieldLocation(end);
			this.end = new FieldLocation(start);
		}
		else {
			this.start = new FieldLocation(start);
			this.end = new FieldLocation(end);
		}
	}

	public FieldRange(FieldRange range) {
		this.start = new FieldLocation(range.start);
		this.end = new FieldLocation(range.end);
	}

	public FieldRange(Element element) {
		start = new FieldLocation(element.getChild("START"));
		end = new FieldLocation(element.getChild("END"));
	}

	public Element getElement() {
		Element element = new Element("RANGE");
		element.addContent(start.getElement("START"));
		element.addContent(end.getElement("END"));
		return element;
	}

	public FieldLocation getStart() {
		return start;
	}

	public FieldLocation getEnd() {
		return end;
	}

	/**
	 * Return string representation for debugging purposes.
	 */
	@Override
	public String toString() {
		return "FieldRange: (" + start + " :: " + end + ")";
	}

	/**
	 * checks if the given location is contained in the range.
	 * @param loc the field location.
	 * @return true if the field range contains the specified location.
	 */
	public boolean contains(FieldLocation loc) {
		return (loc.compareTo(start) >= 0) && (loc.compareTo(end) < 0);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (obj.getClass() != getClass()) {
			return false;
		}
		FieldRange other = (FieldRange) obj;
		return start.equals(other.start) && end.equals(other.end);
	}

	@Override
	public int hashCode() {
		return start.hashCode() << 16 + end.hashCode();
	}

	public int compareTo(FieldRange o) {
		int result = start.compareTo(o.start);
		if (result == 0) {
			result = end.compareTo(o.end);
		}
		return result;
	}

	public boolean canMerge(FieldRange newRange) {
		if (compareTo(newRange) > 0) {
			return newRange.canMerge(this);
		}
		if (end.compareTo(newRange.start) < 0) {
			return false;
		}
		return true;
	}

	public void merge(FieldRange newRange) {
		if (!canMerge(newRange)) {
			throw new AssertException("Attempted to merge a range that can't be merged!");
		}
		if (start.compareTo(newRange.start) > 0) {
			start = newRange.start;
		}
		if (end.compareTo(newRange.end) < 0) {
			end = newRange.end;
		}
	}

	public boolean isEmpty() {
		return start.equals(end);
	}

	public boolean intersects(FieldRange range) {
		if (compareTo(range) > 0) {
			return range.intersects(this);
		}
		return end.compareTo(range.start) > 0;
	}

	public FieldRange intersect(FieldRange range) {
		FieldLocation maxStart = start.compareTo(range.start) >= 0 ? start : range.start;
		FieldLocation minEnd = end.compareTo(range.end) <= 0 ? end : range.end;
		if (maxStart.compareTo(minEnd) >= 0) {
			return null;
		}
		return new FieldRange(maxStart, minEnd);
	}

	public FieldRange subtract(FieldRange deleteRange) {
		if (!intersects(deleteRange)) {
			return null;
		}

		int compareStarts = start.compareTo(deleteRange.start);
		int compareEnds = end.compareTo(deleteRange.end);

		// check for case that splits this FieldRange
		if (compareStarts < 0 && compareEnds > 0) {
			FieldRange tailPiece = new FieldRange(deleteRange.end, end);
			// terminate this range with the delete range start
			end = deleteRange.start;
			return tailPiece;
		}
		// check for case the completely deletes me
		if (compareStarts >= 0 && compareEnds <= 0) {
			end = start;
			return null;
		}
		// case where my tail gets truncated
		if (compareStarts < 0) {
			end = deleteRange.start;
			return null;
		}
		// case where my front gets truncated
		start = deleteRange.end;
		return null;
	}

	public boolean containsEntirely(int index) {
		if (start.getIndex().intValue() > index ||
			((start.getIndex().intValue() == index) && (start.fieldNum != 0 || start.row != 0 || start.col != 0))) {
			return false;
		}
		if (end.getIndex().intValue() <= index) {
			return false;
		}
		return true;
	}

	public boolean containsEntirely(BigInteger index) {
		int compareTo = start.getIndex().compareTo(index);
		if (compareTo > 0 ||
			((compareTo == 0) && (start.fieldNum != 0 || start.row != 0 || start.col != 0))) {
			return false;
		}
		if (end.getIndex().compareTo(index) <= 0) {
			return false;
		}
		return true;
	}

}
