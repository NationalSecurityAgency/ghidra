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
package ghidra.app.plugin.core.functiongraph.graph.layout.flowchart;

import java.util.List;

import ghidra.graph.viewer.layout.GridPoint;

/**
 * Horizontal edge segments of an edge with articulation points. Each pair of points in the list
 * of articulation points corresponds to either a column segment or a row segment. There is
 * a built-in assumption in the compareTo algorithm that the list of articulation points always
 * start and end with a column segment. See {@link EdgeSegment} for more information.
 *
 * @param <E> The edge type
 */
public class RowSegment<E> extends EdgeSegment<E> implements Comparable<RowSegment<E>> {
	// specifies the orientation of the column attached to this segment (either left or right)
	enum ColumnOrientation {
		UP,		// the attached column extends upwards from this row		 
		DOWN	// the attached column extends downwards from this row
	}

	private ColumnSegment<E> next;
	private ColumnSegment<E> previous;

	RowSegment(ColumnSegment<E> previous, E e, List<GridPoint> points, int pointIndex) {
		super(e, points, pointIndex);
		this.previous = previous;
		// row segments always have a follow-on column segment
		this.next = new ColumnSegment<E>(this, e, points, pointIndex + 1);
	}

	/**
	 * Returns the grid row index this row segment.
	 * @return the grid row index this row segment
	 */
	public int getRow() {
		return points.get(pointIndex).row;
	}

	/**
	 * Return the index of the column where this row segment starts. Note that this is different
	 * from the left column. The start column is in the order of the articulation points whereas 
	 * the left column is always the left most spatially column (lower column index) of either the
	 * start column or end column.
	 * @return the index of the grid column for the start point of this segment
	 */
	public int getStartCol() {
		return points.get(pointIndex).col;
	}

	/**
	 * Return the index of the column where this row segment ends. Note that this is different
	 * from the right column. The end column is in the order of the articulation points whereas 
	 * the right column is always the right most spatially column (higher column index) of either
	 * the start column or end column.
	 * @return the index of the grid column for the start point of this segment
	 */
	public int getEndCol() {
		return points.get(pointIndex + 1).col;
	}

	/**
	 * Returns the column index of the left most column of this row segment.
	 * @return the column index of the left most column of this row segment
	 */
	public int getLeftCol() {
		return Math.min(getStartCol(), getEndCol());
	}

	/**
	 * Returns the column index of the right most column of this row segment.
	 * @return the column index of the right most column of this row segment
	 */
	public int getRightCol() {
		return Math.max(getStartCol(), getEndCol());
	}

	@Override
	public int compareTo(RowSegment<E> other) {
		int result = compareLefts(other);
		if (result == 0) {
			result = compareRights(other);
		}
		return result;
	}

	/**
	 * Checks if the given row segment overlaps horizontally.
	 * @param other the other column segment to compare
	 * @return true if these would overlap if drawn with same y row coordinate 
	 */
	public boolean overlaps(RowSegment<E> other) {
		if (getLeftCol() > other.getRightCol()) {
			return false;
		}
		if (getRightCol() < other.getLeftCol()) {
			return false;
		}
		// if the rows are exactly adjacent and if where they touch they are both attached
		// to terminal column segments, then don't consider them to overlap.
		if (getLeftCol() == other.getRightCol()) {
			return !(isLeftTerminal() && other.isRightTerminal());
		}
		else if (getRightCol() == other.getLeftCol()) {
			return !(isRightTerminal() && other.isLeftTerminal());
		}

		return true;
	}

	/**
	 * Compares row segments strictly based  on the relationship of the connected column segments 
	 * at the left of these segments. 
	 * @param other the other row segment to compare
	 * @return  a negative integer, zero, or a positive integer as this object
	 *          is less than, equal to, or greater than the specified object.
	 */
	public int compareLefts(RowSegment<E> other) {
		// first, just check the rows of this segment and the other, if the rows are
		// not the same, then one column clearly above the other.

		int result = getRow() - other.getRow();
		if (result != 0) {
			return result;
		}

		// We are in the same grid row, so the order is determined by the segment at the
		// left of the column. There are 2 possible orientations for the left column. 1) it can
		// extend upwards from our row, or it can extend downwards from our row.
		// If our left orientation is not the same as the other row segment, the order is
		// simply UP < DOWN in order to reduce edge crossings. Edges on the top
		// go up and edges on the bottom go down, so they won't cross each other.
		ColumnOrientation myLeftColOrientation = getOrientationForLeftColumn();
		ColumnOrientation otherLeftColOrientation = other.getOrientationForLeftColumn();

		// if they are not the same, then UP < DOWN
		if (myLeftColOrientation != otherLeftColOrientation) {
			return myLeftColOrientation.compareTo(otherLeftColOrientation);
		}

		// Both this segment's left and the other segment's left have the same orientation. 
		// Compare the left column segments and use those results to determine our ordering 
		// top to bottom. If the left columns extend upward, then which ever column is left most 
		// (lower value), should have it's associated row lower spatially (higher row value)
		// Keeping left most columns(lower value) as lower rows allows their shape to avoid being
		// crossed by the wider shape, which will be lower.
		// 
		// And if the left rows extends downwards, the inverse applies.	
		ColumnSegment<E> myLeftColSegment = getLeftColSegment();
		ColumnSegment<E> otherLeftColSegment = other.getLeftColSegment();

		if (myLeftColOrientation == ColumnOrientation.UP) {
			return -myLeftColSegment.compareTops(otherLeftColSegment);
		}
		return myLeftColSegment.compareBottoms(otherLeftColSegment);
	}

	/**
	 * Compares row segments strictly based  on the relationship of the connected column segments 
	 * at the right of these segments. 
	 * @param other the other row segment to compare
	 * @return  a negative integer, zero, or a positive integer as this object
	 *          is less than, equal to, or greater than the specified object.
	 */
	public int compareRights(RowSegment<E> other) {
		// first, just check the rows of this segment and the other, if the rows are
		// not the same, then one column clearly above the other.
		int result = getRow() - other.getRow();
		if (result != 0) {
			return result;
		}

		// We are in the same grid row, so the order is determined by the segment at the
		// right of the column. There are 2 possible orientations for the right column. 1) it can
		// extend upwards from our row, or it can extend downwards from our row.
		// If our right orientation is not the same as the other row segment, the order is
		// simply UP < DOWN in order to reduce edge crossings. Edges on the top
		// go up and edges on the bottom go down, so they won't cross each other.

		ColumnOrientation myRightColOrientation = getOrientationForRightColumn();
		ColumnOrientation otherRightColOrientation = other.getOrientationForRightColumn();

		// if they are not the same, then UP < DOWN
		if (myRightColOrientation != otherRightColOrientation) {
			return myRightColOrientation.compareTo(otherRightColOrientation);
		}

		// Both this segment's right column and the other segment's right column have the same
		// orientation. Compare the right column segments and use those results to determine our
		// ordering top to bottom. If the right columns extend upward, then which ever column is
		// left most (lower value), should have it's associated row higher spatially (lower row
		// value). Keeping left most columns(lower value) as higher rows (lower values) allows
		// their shape to avoid being crossed by the wider shape, which will be lower.
		// 
		// And if the right rows extends downwards, the inverse applies.	
		ColumnSegment<E> myRightColSegment = getRightColSegment();
		ColumnSegment<E> otherRightColSegment = other.getRightColSegment();

		if (myRightColOrientation == ColumnOrientation.UP) {
			return myRightColSegment.compareTops(otherRightColSegment);
		}
		return -myRightColSegment.compareBottoms(otherRightColSegment);
	}

	@Override
	public ColumnSegment<E> nextSegment() {
		return next;
	}

	@Override
	public ColumnSegment<E> previousSegment() {
		return previous;
	}

	private ColumnOrientation getOrientationForLeftColumn() {
		ColumnSegment<E> leftSegment = getLeftColSegment();
		int leftColOtherRow = flowsLeft() ? leftSegment.getEndRow() : leftSegment.getStartRow();
		return leftColOtherRow < getRow() ? ColumnOrientation.UP : ColumnOrientation.DOWN;
	}

	private ColumnOrientation getOrientationForRightColumn() {
		ColumnSegment<E> rightSegment = getRightColSegment();
		int rightColOtherRow = flowsLeft() ? rightSegment.getStartRow() : rightSegment.getEndRow();
		return rightColOtherRow < getRow() ? ColumnOrientation.UP : ColumnOrientation.DOWN;
	}

	private ColumnSegment<E> getLeftColSegment() {
		return flowsLeft() ? next : previous;
	}

	private ColumnSegment<E> getRightColSegment() {
		return flowsLeft() ? previous : next;
	}

	private boolean flowsLeft() {
		return getStartCol() > getEndCol();
	}

	private boolean isLeftTerminal() {
		ColumnSegment<E> left = getLeftColSegment();
		return left.isStartSegment() || left.isEndSegment();
	}

	private boolean isRightTerminal() {
		ColumnSegment<E> right = getRightColSegment();
		return right.isStartSegment() || right.isEndSegment();
	}

	public ColumnSegment<E> last() {
		return next.last();
	}
}
