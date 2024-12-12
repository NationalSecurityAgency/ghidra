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
 * Vertical edge segments of an edge with articulation points. Each pair of points in the list
 * of articulation points corresponds to either a column segment or a row segment. There is
 * a built-in assumption in the sorting algorithm that the list of articulation points always
 * start and end with a column segment. See {@link EdgeSegment} for more information.
 *
 * @param <E> The edge type
 */
public class ColumnSegment<E> extends EdgeSegment<E> {

	// specifies the orientation of the row attached to this segment (either top or bottom)
	enum RowOrientation {
		LEFT, 		// the attached row extends to the left of this column
		TERMINAL, 	// there is no attached row since this segment ends at a vertex. 
		RIGHT		// the attached row extends to the right of this column
	}

	private RowSegment<E> next;
	private RowSegment<E> previous;

	/**
	 * Constructs the first segment which is always a column segment. This constructor will
	 * also create all the follow-on segments which can be retrieved via the {@link #nextSegment()}
	 * method.
	 * @param e the edge to create segments for
	 * @param points the articulation points for the edge.
	 */
	public ColumnSegment(E e, List<GridPoint> points) {
		this(null, e, points, 0);
	}

	/**
	 * Package method for creating the column segments at a specific pointIndex.
	 * @param previous the row segment the precedes this column segment
	 * @param e the edge this segment is for
	 * @param points the list of articulation points for the edge
	 * @param pointIndex the index into the points list that is the first point for this segment
	 */
	ColumnSegment(RowSegment<E> previous, E e, List<GridPoint> points, int pointIndex) {
		super(e, points, pointIndex);
		this.previous = previous;
		if (pointIndex < points.size() - 2) {
			next = new RowSegment<E>(this, e, points, pointIndex + 1);
		}
	}

	/**
	 * Returns the grid column index this column segment.
	 * @return the grid column index this column segment
	 */
	public int getCol() {
		return points.get(pointIndex).col;
	}

	/**
	 * Return the index of the row where this column segment starts. Note that this is different
	 * from the top row. The start row is in the order of the articulation points whereas the top
	 * row is always the spatially upper (lower row index) row of either the start row or end row.
	 * @return the index of the grid row for the start point of this segment
	 */
	public int getStartRow() {
		return points.get(pointIndex).row;
	}

	/**
	 * Return the index of the row where this column segment ends. Note that this is different
	 * from the bottom row. The end row is in the order of the articulation points. The bottom row
	 * is always the spatially lower (higher row index) row of either the start row or end row.
	 * @return the index of the grid row for the end point of this segment
	 */
	public int getEndRow() {
		return points.get(pointIndex + 1).row;
	}

	public int compareToIgnoreFlows(ColumnSegment<E> other) {
		// When comparing edge segments that have mixed flow directions, we arbitrarily chose to
		// always compare the order by following the shape of the top and only considering the shape
		// on the bottom if the tops are equal. This needs to be consistent so that the comparison
		// is transitive and reversible.
		//
		// NOTE: Segments are compared by following the next or previous segments until one of the
		// segments definitively determines the order. When comparing segments in a particular
		// direction, is is important not to directly call the compareTo methods as that could result
		// in an infinite loop. Instead, when comparing in a particular direction, just directly
		// use the appropriate direction comparison so that it will follow that direction until
		// it finds a difference or it simply returns 0, in which case the original to
		// compareTo can then try the other direction. As a consequence of this, the basic obvious
		// comparison of first comparing the grid column's index had to be moved into both the
		// compareTops and the compareBottoms.

		int result = compareTops(other);
		if (result == 0) {
			result = compareBottoms(other);
		}
		return result;
	}

	public int compareToUsingFlows(ColumnSegment<E> other) {
		// When comparing segments that flow in the same direction, we prefer to compare previous
		// edges first and if they are equal, we compare follow-on edges. This yields better
		// results (less edge crossings) for some edge cases because it allows all the segments
		// in an edge to compare consistently in the same direction which is not guaranteed in 
		// the ignore flow case. However, this comparison can only be used for sorting when all
		// the segments in a list flow in the same direction. Otherwise the comparison is not
		// transitive, which could result in breaking the sort algorithm.

		// NOTE: Segments are compared by following the next or previous segments until one of the
		// segments definitively determines the order. When comparing segments in a particular
		// direction, is is important not to directly call the compareTo methods as that could result
		// in an infinite loop. Instead, when comparing in a particular direction, just directly
		// use the appropriate direction comparison so that it will follow that direction until
		// it finds a difference or it simply returns 0, in which case the original 
		// compareTo can then try the other direction. As a consequence of this, the basic obvious
		// comparison of first comparing the grid column's index had to be moved into both the
		// compareTops and the compareBottoms.

		if (isFlowingUpwards()) {
			int result = compareBottoms(other);
			if (result == 0) {
				result = compareTops(other);
			}
			return result;
		}

		int result = compareTops(other);
		if (result == 0) {
			result = compareBottoms(other);
		}
		return result;
	}

	/**
	 * Compares column segments strictly based  on the relationship of the connected rows at the top
	 * of the segments. 
	 * @param other the other column segment to compare
	 * @return  a negative integer, zero, or a positive integer as this object
	 *          is less than, equal to, or greater than the specified object.
	 */
	public int compareTops(ColumnSegment<E> other) {
		// first, just check the columns of this segment and the other, if the columns are
		// not the same, then one column clearly is to the left of the other. 

		int result = getCol() - other.getCol();
		if (result != 0) {
			return result;
		}

		// We are in the same grid column,so the order is determined by the segment at the
		// top of the column. There are 3 possible orientations for the top row. 1) it can
		// extend to the left of our column, it can be a terminal point, or it can extend to the
		// right. If our orientation is not the same as the other column segment, the order is
		// simply LEFT < TERMINAL < RIGHT in order to reduce edge crossings. Edges on the left
		// go left and edges on the right go right, so they won't cross each other.

		RowOrientation myTopRowOrientation = getOrientationForTopRow();
		RowOrientation otherTopRowOrientation = other.getOrientationForTopRow();

		// if they are not the same, then LEFT < TERMINAL < RIGHT
		if (myTopRowOrientation != otherTopRowOrientation) {
			return myTopRowOrientation.compareTo(otherTopRowOrientation);
		}

		// Both this segment and the other segment have the same orientation. Compare the top
		// row segments and use those results to determine our ordering left to right. If the
		// top rows extend to the left, then which ever row is above (lower value), should have
		// its associated column be to the right (higher value). Keeping lower rows (higher value)
		// on the left allows their shape to avoid being crossed by the taller shape, which will be
		// on the right.
		// 
		// And if the top rows extends the right, the inverse applies.

		switch (myTopRowOrientation) {
			case LEFT:
				RowSegment<E> myTopRowSegment = getTopRowSegment();
				RowSegment<E> otherTopRowSegment = other.getTopRowSegment();
				return -myTopRowSegment.compareLefts(otherTopRowSegment);
			case RIGHT:
				myTopRowSegment = getTopRowSegment();
				otherTopRowSegment = other.getTopRowSegment();
				return myTopRowSegment.compareRights(otherTopRowSegment);
			case TERMINAL:
			default:
				return 0;
		}

	}

	/**
	 * Compares column segments strictly based  on the relationship of the connected rows at the 
	 * bottom of the segments. 
	 * @param other the other column segment to compare
	 * @return  a negative integer, zero, or a positive integer as this object
	 *          is less than, equal to, or greater than the specified object.
	 */
	public int compareBottoms(ColumnSegment<E> other) {
		// first, just check the columns of this segment and the other, if the columns are
		// not the same, then one column clearly is to the left of the other.
		int result = getCol() - other.getCol();
		if (result != 0) {
			return result;
		}

		// We are in the same grid column, the order is determined by the segment at the
		// bottom of the column (we already tried the top and they were equal). There are 
		// 3 possible orientations for the botom row. 1) it can
		// extend to the left of our column, it can be a terminal point, or it can extend to the
		// right. If our orientation is not the same as the other column segment, the order is
		// simply LEFT < TERMINAL < RIGHT in order to reduce edge crossings. Edges on the left
		// go left and edges on the right go right, so they won't cross each other.

		RowOrientation myBottomRowOrientation = getOrientationForBottomRow();
		RowOrientation otherTopRowOrientation = other.getOrientationForBottomRow();
		// if they are not the same, then LEFT < TERMINAL < RIGHT
		if (myBottomRowOrientation != otherTopRowOrientation) {
			return myBottomRowOrientation.compareTo(otherTopRowOrientation);
		}

		// Both this segment and the other segment have the same orientation. Compare the bottom
		// row segments and use those results to determine our ordering left to right. If the
		// bottom rows extend to the left, then which ever row is above (lower value), should have
		// its associated column be to the left (lower value). Keeping lower rows (higher value)
		// on the right allows their shape to avoid being crossed by the taller shape, which will be
		// on the left.
		// 
		// And if the top rows extends the right, the inverse applies.

		switch (myBottomRowOrientation) {
			case LEFT:
				RowSegment<E> myBottomRowSegment = getBottomRowSegment();
				RowSegment<E> otherBottomRowSegment = other.getBottomRowSegment();
				return myBottomRowSegment.compareLefts(otherBottomRowSegment);

			case RIGHT:
				myBottomRowSegment = getBottomRowSegment();
				otherBottomRowSegment = other.getBottomRowSegment();
				return -myBottomRowSegment.compareRights(otherBottomRowSegment);
			case TERMINAL:
			default:
				return 0;
		}

	}

	/**
	 * Checks if the given column segments overlaps vertically.
	 * @param other the other column segment to compare
	 * @return true if these would overlap if drawn with same x column coordinate 
	 */
	public boolean overlaps(ColumnSegment<E> other) {
		if (getVirtualMinY() > other.getVirtualMaxY()) {
			return false;
		}
		if (getVirtualMaxY() < other.getVirtualMinY()) {
			return false;
		}
		return true;
	}

	@Override
	public RowSegment<E> nextSegment() {
		return next;
	}

	@Override
	public RowSegment<E> previousSegment() {
		return previous;
	}

	/**
	 * Returns true if this is the first segment in an edge articulation point list.
	 * @return true if this is the first segment in an edge articulation point list
	 */
	public boolean isStartSegment() {
		return previous == null;
	}

	/**
	 * Returns true if this is the last segment in an edge articulation point list.
	 * @return true if this is the last segment in an edge articulation point list
	 */
	public boolean isEndSegment() {
		return next == null;
	}

	/**
	 * Returns a top y position assuming rows are one million pixels apart for comparison purposes. 
	 * It takes into account the assigned offsets of the attached rows. This method depends on
	 * row offsets having already been assigned.
	 * @return a virtual top y position only useful for comparison purposes.
	 */
	public int getVirtualMinY() {
		return Math.min(getVirtualStartY(), getVirtualEndY());
	}

	/**
	 * Returns a bottom y position assuming rows are one million pixels apart for comparison
	 * purposes. It takes into account the assigned offsets of the attached rows. This method
	 * depends on row offsets having already been assigned.
	 * @return a virtual bottom y position only useful for comparison purposes.
	 */
	public int getVirtualMaxY() {
		return Math.max(getVirtualStartY(), getVirtualEndY());
	}

	private int getVirtualStartY() {
		// start segments are given a slight downward offset for comparison purposes to 
		// avoid being overlapped by ends segments that end on the same vertex as we begin
		int offset = previous == null ? 1 : previous.getOffset();

		return getStartRow() * 1000000 + offset;
	}

	private int getVirtualEndY() {
		// end segments are given a slight upward offset for comparison purposes to 
		// avoid being overlapped by ends segments that start on the same vertex as we end
		int offset = next == null ? -1 : next.getOffset();
		return getEndRow() * 1000000 + offset;
	}

	private RowSegment<E> getTopRowSegment() {
		return isFlowingUpwards() ? next : previous;
	}

	private RowSegment<E> getBottomRowSegment() {
		return isFlowingUpwards() ? previous : next;
	}

	private RowOrientation getOrientationForTopRow() {
		if (isStartSegment()) {
			return RowOrientation.TERMINAL;
		}
		RowSegment<E> topRowSegment = getTopRowSegment();
		int topRowOtherCol =
			isFlowingUpwards() ? topRowSegment.getEndCol() : topRowSegment.getStartCol();
		return topRowOtherCol < getCol() ? RowOrientation.LEFT : RowOrientation.RIGHT;
	}

	private RowOrientation getOrientationForBottomRow() {
		if (isEndSegment()) {
			return RowOrientation.TERMINAL;
		}
		RowSegment<E> bottomRowSegment = getBottomRowSegment();
		int bottomRowOtherCol =
			isFlowingUpwards() ? bottomRowSegment.getStartCol() : bottomRowSegment.getEndCol();
		return bottomRowOtherCol < getCol() ? RowOrientation.LEFT : RowOrientation.RIGHT;
	}

	public boolean isFlowingUpwards() {
		return getStartRow() > getEndRow();
	}

	public ColumnSegment<E> last() {
		if (isEndSegment()) {
			return this;
		}
		return next.last();
	}

}
