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

import java.awt.Rectangle;
import java.awt.Shape;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Function;

import ghidra.graph.viewer.layout.*;

/**
 * Computes positions in layout space for {@link GridLocationMap}s that have orthogonally routed
 * edges.
 * <P>
 * At this point, the grid has been populated with vertices at specific grid points and edges with
 * lists of grid articulation points for their routing. Conceptually, vertices live at the 
 * intersection of the grid lines and edges are routed along grid lines. While in grid space, 
 * vertices have no size and edges can overlap each other along grid lines. In order to map these 
 * virtual grid locations to points in layout space, we need to use the size of each vertex and 
 * offsets assigned to parallel edge segments that share a grid line.
 * <P>
 * We first need to compute sizes for the rows and columns in the grid. For purposes of this
 * algorithm, the size of a row N is defined to be the distance between grid line row N and grid
 * line row N+1. The same applies to column sizes. The way vertex sizes are applied is slightly
 * different for rows and column. Vertices are centered on grid column lines, but
 * completely below grid row lines. So if a vertex is at grid point 1,1, all of its height is 
 * assigned to grid row 1. But its width is split between grid column 0 and grid column 1. Edges
 * work similarly, in that parallel horizontal edge segments extend below their grid row, but 
 * parallel column segments are split so that some have offsets that are before the vertical 
 * grid line and some are after.
 * <P>
 * The row sizing is straight forward. Even rows only contain edges and odd rows only contain
 * vertices. Since the height of a vertex is assigned completely to one row, that row's height
 * is simply the maximum height of all the vertices in that row, plus any row padding.
 * <P>
 * Column sizing is more complicated. The width of any column is going to be the the max of either
 * 1) vertices that half extend from the left + the thickness of edges that extend the right, OR 
 * 2) vertices that half extend from the right + the thickness of edges the extend from the left.
 * Also, column padding is applied differently. For columns, padding is not just added to the 
 * column width like in rows. Instead, it acts as a minimum "edge thickness". In other words if the
 * edge thickness is less than the padding, the edge thickness doesn't make the gaps bigger. Only if
 * the edge thickness is greater the the column padding, then it determines the gap and the 
 * column padding contributes nothing.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class OrthogonalGridSizer<V, E> {
	private static final int EDGE_ROW_PADDING = 25;				// space before an edge row
	private static final int VERTEX_ROW_PADDING = 35;			// space before a vertex vow
	private static final int COL_PADDING = 30;					// minimum space for a column
	private static final int CONDENSED_EDGE_ROW_PADDING = 15;
	private static final int CONDENSED_VERTEX_ROW_PADDING = 25;
	private static final int CONDENSED_COL_PADDING = 15;

	private int[] rowHeights;
	private int[] beforeColEdgeWidths;
	private int[] afterColEdgeWidths;
	private int[] colVertexWidths;
	private int edgeSpacing;

	public OrthogonalGridSizer(GridLocationMap<V, E> gridMap, EdgeSegmentMap<E> segmentMap,
			Function<V, Shape> transformer, int edgeSpacing) {
		this.edgeSpacing = edgeSpacing;
		rowHeights = new int[gridMap.height()];
		beforeColEdgeWidths = new int[gridMap.width()];
		afterColEdgeWidths = new int[gridMap.width()];
		colVertexWidths = new int[gridMap.width()];

		addVertexSizes(gridMap, transformer);

		addEdgeRowSizes(gridMap, segmentMap);

		addEdgeColSizes(gridMap, segmentMap);
	}

	public GridCoordinates getGridCoordinates(boolean isCondensed) {
		int[] rowStarts = new int[rowCount() + 1];
		int[] colStarts = new int[colCount() + 1];
		int vertexRowPadding = isCondensed ? CONDENSED_VERTEX_ROW_PADDING : VERTEX_ROW_PADDING;
		int edgeRowPadding = isCondensed ? CONDENSED_EDGE_ROW_PADDING : EDGE_ROW_PADDING;
		int colPadding = isCondensed ? CONDENSED_COL_PADDING : COL_PADDING;
		for (int row = 1; row < rowStarts.length; row++) {
			// edges rows are even, vertex rows are odd
			int rowPadding = row % 2 == 0 ? edgeRowPadding : vertexRowPadding;
			rowStarts[row] = rowStarts[row - 1] + height(row - 1, rowPadding);
		}
		for (int col = 1; col < colStarts.length; col++) {
			colStarts[col] = colStarts[col - 1] + width(col - 1, colPadding);
		}

		return new GridCoordinates(rowStarts, colStarts);
	}

	private int rowCount() {
		return rowHeights.length;
	}

	private int colCount() {
		return colVertexWidths.length;
	}

	private int height(int row, int rowPadding) {
		return rowHeights[row] + rowPadding;
	}

	private int width(int col, int minColPadding) {
		int leftEdgeWidth = Math.max(afterColEdgeWidths[col], minColPadding);
		int leftVertexWidth = colVertexWidths[col] / 2;
		int rightEdgeWidth = 0;
		int rightVertexWidth = 0;
		if (col < colVertexWidths.length - 1) {
			rightEdgeWidth = Math.max(beforeColEdgeWidths[col + 1], minColPadding);
			rightVertexWidth = colVertexWidths[col + 1] / 2;
		}

		int width = Math.max(leftEdgeWidth + rightVertexWidth, rightEdgeWidth + leftVertexWidth);
		width = Math.max(width, leftEdgeWidth + rightEdgeWidth);
		return width;
	}

	private void addEdgeColSizes(GridLocationMap<V, E> gridMap, EdgeSegmentMap<E> segmentMap) {
		for (ColSegmentList<E> colSegments : segmentMap.colSegments()) {
			int col = colSegments.getCol();
			int edgesToLeft = -colSegments.getMinOffset();
			int edgesToRight = colSegments.getMaxOffset();
			addColumnEdgeWidth(col, edgesToLeft * edgeSpacing, edgesToRight * edgeSpacing);
		}
	}

	private void addEdgeRowSizes(GridLocationMap<V, E> gridMap, EdgeSegmentMap<E> segmentMap) {
		// edge rows have no vertices, so its height just depends on the number of parallel edges
		for (RowSegmentList<E> rowSegments : segmentMap.rowSegments()) {
			int row = rowSegments.getRow();
			int edgeCount = rowSegments.getMaxOffset() - rowSegments.getMinOffset();
			addRowHeight(row, edgeCount * edgeSpacing);
		}
	}

	private void addVertexSizes(GridLocationMap<V, E> gridMap, Function<V, Shape> transformer) {
		Map<V, GridPoint> vertexPoints = gridMap.getVertexPoints();

		for (Entry<V, GridPoint> entry : vertexPoints.entrySet()) {
			V v = entry.getKey();
			GridPoint p = entry.getValue();
			Shape shape = transformer.apply(v);
			Rectangle vertexBounds = shape.getBounds();
			addRowHeight(p.row, vertexBounds.height);
			addColumnVertexWidth(p.col, vertexBounds.width);
		}
	}

	private void addRowHeight(int row, int height) {
		rowHeights[row] = Math.max(rowHeights[row], height);
	}

	private void addColumnVertexWidth(int col, int width) {
		colVertexWidths[col] = Math.max(colVertexWidths[col], width);
	}

	private void addColumnEdgeWidth(int col, int beforeWidth, int afterWidth) {
		beforeColEdgeWidths[col] = Math.max(beforeColEdgeWidths[col], beforeWidth);
		afterColEdgeWidths[col] = Math.max(afterColEdgeWidths[col], afterWidth);
	}

}
