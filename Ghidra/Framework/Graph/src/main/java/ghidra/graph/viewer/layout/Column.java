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
import java.util.Map.Entry;

import ghidra.graph.viewer.GraphViewerUtils;

/**
 * A column in a grid.   This class stores its column index, its x offset and its width.  The
 * x value is the layout space x value of a {@link Point2D} object.   That is, unlike the
 * {@link GridLocationMap}, the x value of this object is in layout space and not indexes 
 * of a grid.
 * 
 * <p>This class maintains a collection of vertices on this column, organized by column index.  You
 * can get the column of a vertex from {@link #getRow(Object)}.
 * @param <V> The vertex type
 */
public class Column<V> {

	/** The <b>layout</b> x coordinate of the column */
	public int x = -1;
	public int width = -1;

	/** The grid index of this column (0, 1...n) for the number of columns */
	public int index = Integer.MAX_VALUE;
	// Note: these must change together (they are effectively a BiDi map)
	private TreeMap<Integer, V> verticesByRow = new TreeMap<>();
	private Map<V, Integer> rowsByVertex = new HashMap<>();

	public Column(int index) {
		this.index = index;
	}

	public void setRow(V v, int row) {
		rowsByVertex.put(v, row);
		verticesByRow.put(row, v);
	}

	public int getRow(V v) {
		if (!rowsByVertex.containsKey(v)) {
			throw new IllegalArgumentException("Vertex is not in row: " + v);
		}
		return rowsByVertex.get(v);
	}

	public int getPaddedWidth(boolean isCondensed) {
		if (isCondensed) {
			return width + GraphViewerUtils.EXTRA_LAYOUT_COLUMN_SPACING_CONDENSED;
		}
		return width + GraphViewerUtils.EXTRA_LAYOUT_COLUMN_SPACING;
	}

	public boolean isInitialized() {
		return x > -1 && width > -1 && index > Integer.MAX_VALUE;
	}

	@Override
	public String toString() {

		//@formatter:off
		return getClass().getSimpleName() + "{\n" +
			"\tcolumn: " + index + ",\n" +
			"\tx: " + x + ",\n" +
			"\twidth: " + width + ",\n" +
			"\tpadded width: " + getPaddedWidth(false) + "\n" +
		"}";
		//@formatter:on
	}

	public boolean isOpenBetween(int startRow, int endRow) {
		Entry<Integer, V> ceilingEntry = verticesByRow.ceilingEntry(startRow);
		if (ceilingEntry == null) {
			return true;
		}
		int nextRow = ceilingEntry.getKey();
		return nextRow > endRow;
	}
}
