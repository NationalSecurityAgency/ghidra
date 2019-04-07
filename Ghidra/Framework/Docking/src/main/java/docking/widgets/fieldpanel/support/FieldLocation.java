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
package docking.widgets.fieldpanel.support;

import java.math.BigInteger;

import org.jdom.Element;

/**
 * Class to represent locations within the FieldViewer.
 */
public class FieldLocation implements Comparable<FieldLocation> {
	public static final FieldLocation MAX =
		new FieldLocation(Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE,
			Integer.MAX_VALUE);

	public int fieldNum; // the number of the field for this location
	public int row; // the row  position within the field .
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

	public BigInteger getIndex() {
		return index;
	}

	/**
	 * Returns the field index for this location.
	 */
	public int getFieldNum() {
		return fieldNum;
	}

	/**
	 * Returns the row within the Field for this location.
	 */
	public int getRow() {
		return row;
	}

	/**
	 * Returns the column within the Field for this location.
	 */
	public int getCol() {
		return col;
	}

	/**
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
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

	/**
	 * 
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return index.intValue() + fieldNum * 100 + row * 10 + col;
	}

	/**
	 * 
	 * @see java.lang.Object#toString()
	 */
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
