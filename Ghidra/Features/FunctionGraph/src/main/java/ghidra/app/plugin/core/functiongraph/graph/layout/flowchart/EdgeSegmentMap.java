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

import ghidra.graph.viewer.layout.GridLocationMap;
import ghidra.graph.viewer.layout.GridPoint;

/**
 * Organizes all edge segments from a {@link GridLocationMap} into rows and column objects and 
 * then assigns offsets to overlapping segments within a row or column. Offsets are values that
 * represent either x or y distances that will later be added to a row segment's y coordinate or a
 * column segment's x coordinate to keep them from overlapping in layout space.
 * <P>
 * The offsets have to be computed before sizing the grid because the offsets affect
 * the size of the grid rows and columns.
 *
 * @param <E> the edge type
 */
public class EdgeSegmentMap<E> {

	private Map<Integer, RowSegmentList<E>> rowSegmentMap = new HashMap<>();
	private Map<Integer, ColSegmentList<E>> colSegmentMap = new HashMap<>();

	public EdgeSegmentMap(GridLocationMap<?, E> grid) {
		createEdgeSegments(grid);
		assignEdgeSegmentOffsets();
	}

	/**
	 * Returns a collection of all edge row segment lists.
	 * @return a collection of all edge row segment lists
	 */
	public Collection<RowSegmentList<E>> rowSegments() {
		return rowSegmentMap.values();
	}

	/**
	 * Returns a collection of all edge column segment lists.
	 * @return a collection of all edge column segment lists
	 */
	public Collection<ColSegmentList<E>> colSegments() {
		return colSegmentMap.values();
	}

	/**
	 * Finds the column segment object for the given edge and start point.
	 * @param edge the edge for which to find its column segment object
	 * @param gridPoint the start point for the desired segment object
	 * @return the column segment object for the given edge and start point.
	 */
	public ColumnSegment<E> getColumnSegment(E edge, GridPoint gridPoint) {
		ColSegmentList<E> colSegments = colSegmentMap.get(gridPoint.col);
		return colSegments == null ? null : colSegments.getSegment(edge, gridPoint);
	}

	public void dispose() {
		rowSegmentMap.clear();
		colSegmentMap.clear();
	}

	private void createEdgeSegments(GridLocationMap<?, E> grid) {
		for (E edge : grid.edges()) {

			List<GridPoint> gridPoints = grid.getArticulations(edge);
			ColumnSegment<E> colSegment = new ColumnSegment<E>(edge, gridPoints);

			addColSegment(colSegment);

			// segments always start and end with a column segment, so any additional segments
			// will be in pairs of a row segment followed by a column segment
			while (!colSegment.isEndSegment()) {
				RowSegment<E> rowSegment = colSegment.nextSegment();
				addRowSegment(rowSegment);
				colSegment = rowSegment.nextSegment();
				addColSegment(colSegment);
			}
		}
	}

	private void assignEdgeSegmentOffsets() {
		for (RowSegmentList<E> rowSegments : rowSegmentMap.values()) {
			rowSegments.assignOffsets();
		}
		for (ColSegmentList<E> colSegments : colSegmentMap.values()) {
			colSegments.assignOffsets();
		}
	}

	private void addRowSegment(RowSegment<E> rowSegment) {
		int row = rowSegment.getRow();
		RowSegmentList<E> edgeRow =
			rowSegmentMap.computeIfAbsent(row, k -> new RowSegmentList<E>(k));
		edgeRow.addSegment(rowSegment);
	}

	private void addColSegment(ColumnSegment<E> colSegment) {
		int col = colSegment.getCol();
		ColSegmentList<E> edgeCol =
			colSegmentMap.computeIfAbsent(col, k -> new ColSegmentList<E>(k));
		edgeCol.addSegment(colSegment);
	}

}
