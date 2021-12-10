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
package ghidra.graph.viewer.layout;

import java.awt.geom.Point2D;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import ghidra.graph.viewer.GraphViewerUtils;

/**
 * A row in a grid.   This class stores its row index, its y offset and its height.   The
 * y value is the layout space y value of a {@link Point2D} object.   That is, unlike the
 * {@link GridLocationMap}, the y value of this object is in layout space and not indexes 
 * of a grid.
 * 
 * <p>This class maintains a collection of vertices on this row, organized by column index.  You
 * can get the column of a vertex from {@link #getColumn(Object) getColumn(V)}.
 * 
 * @param <V> the vertex type
 */
public class Row<V> {

	/** The <b>layout</b> y coordinate of the column */
	public int y = -1;
	public int height = -1;

	/** The grid index of this row (0, 1...n) for the number of rows */
	public int index = Integer.MAX_VALUE;

	// Note: this must change together (they are effectively a BiDi map)
	private TreeMap<Integer, V> verticesByColumn = new TreeMap<>();
	private Map<V, Integer> columnsByVertex = new HashMap<>();

	Row() {
		// default; index not yet known
	}

	Row(int index) {
		this.index = index;
	}

	/**
	 * Sets the column index in this row for the given vertex
	 * 
	 * @param v the vertex
	 * @param col the column index 
	 */
	public void setColumn(V v, int col) {
		columnsByVertex.put(v, col);
		verticesByColumn.put(col, v);
	}

	/**
	 * Returns the column index for the given vertex
	 * 
	 * @param v the vertex 
	 * @return the column index for the given vertex
	 */
	public int getColumn(V v) {
		if (!columnsByVertex.containsKey(v)) {
			throw new IllegalArgumentException("Vertex is not in row: " + v);
		}
		return columnsByVertex.get(v);
	}

	/**
	 * Returns the vertex at the given column index or null if there is no vertex at that column
	 * 
	 * @param column the column index
	 * @return the vertex
	 */
	public V getVertex(int column) {
		return verticesByColumn.get(column);
	}

	/**
	 * Represents the range of columns in this row.  For this given row in a grid:
	 * <pre>
	 * 	0 1 2 3 4 5 6
	 * 	- - v - v - - 
	 * </pre>
	 * the column count is 3--where the column range is 2-4, inclusive.   
	 * 
	 * <p>Note: this differs from then number of vertices in this row, as the column count
	 * includes columns that have no vertex.
	 * 
	 * @return the number of columns in this row, including empty columns between start and end
	 */
	public int getColumnCount() {
		if (verticesByColumn.isEmpty()) {
			return 0;
		}
		Integer largestColumn = verticesByColumn.lastKey();
		Integer smallestColumn = verticesByColumn.firstKey();
		int diff = Math.abs(largestColumn - smallestColumn); // abs for negative column values
		return diff + 1; // +1 for zero-based values
	}

	/**
	 * Returns the smallest column index in this row
	 * 
	 * @return the smallest column index in this row
	 */
	public Integer getStartColumn() {
		return verticesByColumn.firstKey();
	}

	/**
	 * Returns the largest column index in this row
	 * 
	 * @return the largest column index in this row
	 */
	public int getEndColumn() {
		return verticesByColumn.lastKey();
	}

	/**
	 * Returns all vertices in this row, sorted by column index (min to max).   
	 * 
	 * <p>Note: the index of a vertex in the list does not match the column index.  To get the
	 * column index for a vertex, call {@link #getColumn(Object) getColumn(V)}.
	 * 
	 * @return all vertices in this row
	 */
	public List<V> getVertices() {

		// fill a list with vertices or null values
		//@formatter:off
		Integer start = verticesByColumn.firstKey();
		Integer n = getColumnCount();
		IntStream columnIndexes = IntStream.range(start, start + n);
		List<V> vertices = 
			columnIndexes
			.mapToObj(col -> verticesByColumn.get(col))
			.filter(v -> v != null)
			.collect(Collectors.toList())
			;
		//@formatter:on
		return vertices;
	}

	public int getPaddedHeight(boolean isCondensed) {
		if (!isCondensed) {
			return height + GraphViewerUtils.EXTRA_LAYOUT_ROW_SPACING;
		}

		if (height == 0) {
			return 0;
		}

		return height + GraphViewerUtils.EXTRA_LAYOUT_ROW_SPACING_CONDENSED;
	}

	public boolean isInitialized() {
		return y > -1 && height > -1 && index > Integer.MAX_VALUE;
	}

	@Override
	public String toString() {

		//@formatter:off
		return getClass().getSimpleName() + "{\n" +
			"\trow: " + index + ",\n" +
			"\ty: " + y + ",\n" +
			"\theight: " + height + ",\n" +
			"\tpadded height: " + getPaddedHeight(false) + ",\n" +
			"\tcolumn count: " + getColumnCount() + "\n" +
		"}";
		//@formatter:on
	}

	void dispose() {
		verticesByColumn.clear();
		columnsByVertex.clear();
	}
}
