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

import java.math.BigInteger;

import org.jdom.Element;

import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.field.Field;

/**
 * Class to represent {@link Field} locations within the field viewer.
 * <p>
 * A field location represents a place within a Field.  Fields live within a concept we call a
 * layout.   A layout represents an 'item', for example an address, along with a grouping of
 * related information.   Each layout will contain one or more Field objects.   Further, each
 * layout's fields may have varying shapes, such as single or multiple rows within the layout.
 * Thusly, a layout could conceptually represent a single line of text or multiple groupings of
 * text and images, similar to how a newspaper or web page is laid out.
 * <p>
 * A layout lives in a larger collection of layouts, which are laid out vertically.  The index of a
 *  layout is its position within that larger list.  This class contains the index of the layout
 *  within which it lives.
 * <p>
 * A {@link FieldSelection} may be within a single layout or may cross multiple layouts.  To
 * determine if a selection crosses multiple layouts, you can get the {@link FieldRange range} of
 * the selection.   You can then use the range's start and end locations to determine if the
 * selection spans multiple layouts.   If the start and end indexes of the range are the same, then
 * the selection is within a single layout; otherwise, the selection spans multiple layouts.
 * <p>
 * This location also contains row and column values.  These values refer to the row and column of
 * text within a single Field.   Lastly, this class contains a field number, which represents the
 * relative field number inside of the over layout, which may contain multiple fields.
 * 
 * @see FieldSelection
 * @see FieldRange
 * @see Layout
 */
public class FieldLocation implements Comparable<FieldLocation> {
	public static final FieldLocation MAX =
		new FieldLocation(Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE,
			Integer.MAX_VALUE);

	public int fieldNum; // the number of the field for this location
	public int row; // the row position within the field 
	public int col; // the col position within the field

	private BigInteger index;

	public FieldLocation() {
		this(BigInteger.ZERO, 0, 0, 0);
	}

	public FieldLocation(int index) {
		this(index, 0, 0, 0);
	}

	public FieldLocation(int index, int fieldNum) {
		this(index, fieldNum, 0, 0);
	}

	public FieldLocation(BigInteger index) {
		this(index, 0, 0, 0);
	}

	public FieldLocation(BigInteger index, int fieldNum) {
		this(index, fieldNum, 0, 0);
	}

	/**
	 * Construct a new FieldLocation with the given index,fieldNum,row, and col.
	 * @param index the index of the layout containing the location
	 * @param fieldNum the index of the field in the layout containing the location
	 * @param row the text row in the field containing the location.
	 * @param col the character position the row containing the location.
	 */
	public FieldLocation(int index, int fieldNum, int row, int col) {
		this(BigInteger.valueOf(index), fieldNum, row, col);
	}

	public FieldLocation(BigInteger index, int fieldNum, int row, int col) {
		this.index = index;
		this.fieldNum = fieldNum;
		this.row = row;
		this.col = col;
	}

	public FieldLocation(Element child) {
		String bigIndexAttribute = child.getAttributeValue("B");
		if (bigIndexAttribute != null) {
			index = new BigInteger(bigIndexAttribute);
		}
		else {
			int value = Integer.parseInt(child.getAttributeValue("I"));
			index = BigInteger.valueOf(value);
		}
		fieldNum = Integer.parseInt(child.getAttributeValue("F"));
		row = Integer.parseInt(child.getAttributeValue("R"));
		col = Integer.parseInt(child.getAttributeValue("C"));
	}

	/**
	 * Construct a new FieldLocation by copying from another FieldLocation.
	 * @param loc the FieldLocation to be copied.
	 */
	public FieldLocation(FieldLocation loc) {
		this(loc.index, loc.fieldNum, loc.row, loc.col);
	}

	/**
	 * Returns the index for this location.  The index corresponds to the layout that contains
	 * the field represented by this location.  See the javadoc header for more details.
	 * @return the index for this location.
	 */
	public BigInteger getIndex() {
		return index;
	}

	/**
	 * Returns the number of the field for this location.  This is the number of the field within
	 * a given layout.  See the javadoc header for more details.
	 * @return the number of the field for this location.
	 */
	public int getFieldNum() {
		return fieldNum;
	}

	/**
	 * Returns the row within the Field for this location.
	 * @return the row within the Field for this location.
	 */
	public int getRow() {
		return row;
	}

	/**
	 * Returns the column within the Field for this location.
	 * @return the column within the Field for this location.
	 */
	public int getCol() {
		return col;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof FieldLocation)) {
			return false;
		}
		FieldLocation loc = (FieldLocation) obj;
		if (index.equals(loc.index) && (fieldNum == loc.fieldNum) && (row == loc.row) &&
			(col == loc.col)) {

			return true;
		}

		return false;
	}

	@Override
	public int compareTo(FieldLocation o) {
		int compareTo = index.compareTo(o.index);
		if (compareTo != 0) {
			return compareTo;
		}
		if (fieldNum < o.fieldNum) {
			return -1;
		}
		if (fieldNum > o.fieldNum) {
			return 1;
		}
		if (row < o.row) {
			return -1;
		}
		if (row > o.row) {
			return 1;
		}
		if (col < o.col) {
			return -1;
		}
		if (col > o.col) {
			return 1;
		}
		return 0;
	}

	@Override
	public int hashCode() {
		return index.intValue() + fieldNum * 100 + row * 10 + col;
	}

	@Override
	public String toString() {
		return index.toString() + ", " + fieldNum + ", " + row + ", " + col;

	}

	public Element getElement(String name) {
		Element element = new Element(name);
		element.setAttribute("B", index.toString());
		element.setAttribute("F", Integer.toString(fieldNum));
		element.setAttribute("R", Integer.toString(row));
		element.setAttribute("C", Integer.toString(col));
		return element;
	}

	public void set(FieldLocation loc) {
		index = loc.index;
		fieldNum = loc.fieldNum;
		row = loc.row;
		col = loc.col;
	}

	public void setIndex(BigInteger index) {
		this.index = index;
	}

}
