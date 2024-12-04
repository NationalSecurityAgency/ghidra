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

import java.util.*;
import java.util.function.Function;

import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.graph.viewer.layout.*;

/**
 * Routes edges orthogonally for vertices positioned in a {@link GridLocationMap}.
 * This algorithm creates articulation points such that outgoing edges always exit the
 * start vertex from the bottom and enter the end vertex from the top.
 * <P>
 * There are only three types of edges created by this algorithm. The first
 * type is an edge with one segment that goes directly from a start vertex straight down to an 
 * end vertex. 
 * <P>
 * The second type is an edge with three segments that goes down from the start vertex,
 * goes left or right to the column of the end vertex and then goes down to a child vertex.
 * <P>
 * The third type consists of 5 segments and can connect any two vertices in the graph. It starts
 * by going down to the next row from the start vertex, then goes left or right until it finds a 
 * column where there are no vertices between that row and the row above the end vertex. It then 
 * goes left or right in that row to the column of the end vertex and then down to that vertex. 
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */

public class OrthogonalEdgeRouter<V extends VisualVertex, E extends VisualEdge<V>> {
	private Function<E, GridRange> excludedColumnsFunction;
	private GridLocationMap<V, E> grid;
	private Map<Integer, Column<V>> columnMap;

	public OrthogonalEdgeRouter(GridLocationMap<V, E> grid) {
		this.grid = grid;
		columnMap = grid.columnsMap();
		excludedColumnsFunction = e -> new GridRange();
	}

	/**
	 * Computes a list of articulations points in grid space for each edge in the given collection 
	 * and sets those points into the {@link GridLocationMap}.
	 * @param edges computes articulations points in grid space and sets them on the grid
	 */
	public void computeAndSetEdgeArticulations(Collection<E> edges) {
		for (E e : edges) {
			V v1 = e.getStart();
			V v2 = e.getEnd();
			GridPoint p1 = grid.gridPoint(v1);
			GridPoint p2 = grid.gridPoint(v2);
			int routingCol = findRoutingColumn(e, p1, p2);
			List<GridPoint> edgePoints = getEdgePoints(p1, p2, routingCol);
			grid.setArticulations(e, edgePoints);
		}
	}

	/**
	 * Sets a function that can be used to prevent edges from being routed in  a range of columns.
	 * One use of this is to prevent back edges from intersecting any child trees in its ancestor
	 * hierarchy between the start vertex and the end vertex.  
	 * @param excludedColumnsFunction the function to call to compute a range of columns to 
	 * prevent routing edges.
	 */
	public void setColumnExclusionFunction(Function<E, GridRange> excludedColumnsFunction) {
		this.excludedColumnsFunction = excludedColumnsFunction;
	}

	private int findRoutingColumn(E e, GridPoint p1, GridPoint p2) {
		if (p2.row == p1.row + 2) {
			return p1.col;			// direct child 
		}
		int startRow = Math.min(p1.row + 1, p2.row - 1);
		int endRow = Math.max(p1.row + 1, p2.row - 1);
		int startCol = Math.min(p1.col, p2.col);
		int endCol = Math.max(p1.col, p2.col);
		boolean isBackEdge = p2.row <= p1.row;

		// If not a back edge, try to route in between start and end columns, but we decided not
		// to ever route back edges in between so that back edges have C-shape or backwards C-shape
		// and not a Z-shape.
		if (!isBackEdge) {
			// try if either start or end column is open
			if (isOpenPath(p1.col, startRow, endRow)) {
				return p1.col;
			}
			if (isOpenPath(p2.col, startRow, endRow)) {
				return p2.col;
			}

			for (int col = startCol + 1; col <= endCol - 1; col++) {
				if (isOpenPath(col, startRow, endRow)) {
					return col;
				}
			}
		}

		// Get an optional excluded range where we don't want to route a specific edge. By
		// default the range is empty, allowing any column.
		GridRange excludedRange = excludedColumnsFunction.apply(e);

		// try each each left and right column expanding outwards, starting at the columns of
		// the start and end vertex.
		for (int i = 1; i <= startCol; i++) {
			int left = startCol - i;
			int right = endCol + i;

			boolean leftExcluded = excludedRange.contains(left);
			boolean rightExcluded = excludedRange.contains(right);
			boolean leftValid = !leftExcluded && isOpenPath(left, startRow, endRow);
			boolean rightValid = !rightExcluded && isOpenPath(right, startRow, endRow);
			if (leftValid) {
				if (!rightValid) {
					return left;
				}
				// if both are open, prefer left for forward edges, right for back edges
				return p1.row < p2.row ? left : right;
			}
			else if (rightValid) {
				return right;
			}
		}
		return 0;	// 0 is always open as we avoid putting vertices in the 0 column
	}

	private boolean isOpenPath(int col, int startRow, int endRow) {
		Column<V> column = columnMap.get(col);
		if (column == null) {
			return true;
		}
		return column.isOpenBetween(startRow, endRow);
	}

	private List<GridPoint> getEdgePoints(GridPoint p1, GridPoint p2, int routingCol) {
		List<GridPoint> points = new ArrayList<GridPoint>();

		points.add(p1);

		if (routingCol == p1.col) {
			if (routingCol != p2.col) {
				points.add(new GridPoint(p2.row - 1, p1.col));
				points.add(new GridPoint(p2.row - 1, p2.col));
			}
		}
		else {
			points.add(new GridPoint(p1.row + 1, p1.col));
			points.add(new GridPoint(p1.row + 1, routingCol));
			if (routingCol != p2.col) {
				points.add(new GridPoint(p2.row - 1, routingCol));
				points.add(new GridPoint(p2.row - 1, p2.col));
			}
		}
		points.add(p2);
		return points;
	}

}
