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
 * Base class for edge segments that are part of an articulated edge. Basically, edge articulations
 * are stored as a list of {@link GridPoint}s while in grid space. Each pair of points in the list
 * of points represents either a row or column segment. These segments are useful for orthogonal 
 * edge routing algorithms as they provide a higher level API instead of dealing directly with
 * the points list.
 * <P>
 * Each segment has its related edge object and the full list of articulation points so that can
 * also provide information on its connected segments. The point index is simply the index into
 * the points list of the first point in the segment that this segment object represents.
 * <P>
 * Segments also maintain a linked list to the other segments that make up the edge which can
 * be retrieved via the {@link #nextSegment()} and {@link #previousSegment()} methods respectively.
 *
 * @param <E> the edge type
 */
public abstract class EdgeSegment<E> {

	protected E edge;
	protected List<GridPoint> points; // this is a list of all articulations points for the edge
	protected int pointIndex;	 	  // the index into the points of the first point in the segment
	private int offset;				  // holds any offset assigned to this segment by edge routing

	public EdgeSegment(E e, List<GridPoint> points, int pointIndex) {
		this.edge = e;
		this.points = points;
		this.pointIndex = pointIndex;
	}

	public E getEdge() {
		return edge;
	}

	/**
	 * Sets the offset from the grid line for this segment. Edge routing algorithms will set
	 * this value to keep overlapping segments in the same row or column for being assigned to
	 * the same exact layout space location.
	 * @param offset the distance from the grid line to use when assigning to layout space
	 */
	public void setOffset(int offset) {
		this.offset = offset;
	}

	/**
	 * The amount of x or y space to use when assigning to layout space to prevent this segment
	 * from overlapping segments from other edges.
	 * @return the offset from the grid line.
	 */
	public int getOffset() {
		return offset;
	}

	@Override
	public String toString() {
		return String.format("%s,  i = %d, offset = %s", edge, pointIndex, offset);
	}

	/**
	 * Returns true if this edge ends at or above its start row.
	 * @return true if this edge ends at or above its start row
	 */
	public boolean isBackEdge() {
		GridPoint start = points.get(0);
		GridPoint end = points.get(points.size() - 1);
		return start.row >= end.row;
	}

	/**
	 * Returns true if this segment starts at the given point. 
	 * @param p the grid point to check
	 * @return true if this segment starts at the given point
	 */
	public boolean startsAt(GridPoint p) {
		return points.get(pointIndex).equals(p);
	}

	/**
	 * Returns the next edge segment after this one or null if this is the last segment. If the
	 * this segment is a RowSegment, the next segment will be a ColumnSegment and vise-versa.
	 * @return the next edge segment.
	 */
	public abstract EdgeSegment<E> nextSegment();

	/**
	 * Returns the previous edge segment before this one or null if this is the first segment. If 
	 * the this segment is a RowSegment, the previous segment will be a ColumnSegment and 
	 * vise-versa.
	 * @return the previous edge segment.
	 */
	public abstract EdgeSegment<E> previousSegment();
}
