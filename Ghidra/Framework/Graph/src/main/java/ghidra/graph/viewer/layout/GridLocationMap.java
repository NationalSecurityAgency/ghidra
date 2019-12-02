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

import java.awt.Point;
import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.collections4.Factory;
import org.apache.commons.collections4.map.LazyMap;

/**
 * An object that maps vertices to rows and columns and edges to their articulation points.  
 * This class is essentially a container that allows layout algorithms to store results, which
 * can later be turned into layout positioning points.   The integer point values in this 
 * class are row, column grid values, starting at 0,0.
 * 
 * <P>Note: the Point2D values for the edge articulations use x,y values that are row and 
 * column index values, the same values as calling {@link #row(Object) row(V)} and {@link #col(Object) col(V)}.
 *
 * <P>After building the grid using this class, clients can call {@link #rows()} to get 
 * high-order object that represent rows.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class GridLocationMap<V, E> {

	private Factory<Point> rowColFactory = () -> new Point();

	private Map<V, Point> vertexPoints = LazyMap.lazyMap(new HashMap<V, Point>(), rowColFactory);
	private Map<E, List<Point>> edgePoints = new HashMap<>();

	Set<V> vertices() {
		return vertexPoints.keySet();
	}

	Set<E> edges() {
		return edgePoints.keySet();
	}

	public void setArticulations(E edge, List<Point> articulations) {
		edgePoints.put(edge, articulations);
	}

	public List<Point> getArticulations(E edge) {
		List<Point> list = edgePoints.get(edge);
		if (list == null) {
			return Collections.emptyList();
		}
		return list;
	}

	public void row(V vertex, int row) {
		vertexPoints.get(vertex).y = row;
	}

	public void col(V vertex, int col) {
		vertexPoints.get(vertex).x = col;
	}

	public void set(V v, int row, int col) {
		Point p = vertexPoints.get(v);
		p.x = col;
		p.y = row;
	}

	public int row(V vertex) {
		return vertexPoints.get(vertex).y;
	}

	public int col(V vertex) {
		return vertexPoints.get(vertex).x;
	}

	/**
	 * Returns the rows in this grid, sorted by index (index can be negative)
	 * 
	 * @return the rows in this grid
	 */
	public List<Row<V>> rows() {

		Map<Integer, Row<V>> rowsByIndex = new HashMap<>();

		Set<Entry<V, Point>> entrySet = vertexPoints.entrySet();
		for (Entry<V, Point> entry : entrySet) {
			V v = entry.getKey();
			Point gridPoint = entry.getValue();
			int rowIndex = gridPoint.y;
			Row<V> row = getRow(rowsByIndex, rowIndex);
			row.index = rowIndex;
			row.setColumn(v, gridPoint.x);
		}

		List<Row<V>> rows = new ArrayList<>(rowsByIndex.values());
		rows.sort((r1, r2) -> r1.index - r2.index);
		return rows;
	}

	private Row<V> getRow(Map<Integer, Row<V>> rows, int rowIndex) {
		Row<V> row = rows.get(rowIndex);
		if (row == null) {
			row = new Row<>(rowIndex);
			rows.put(rowIndex, row);
		}
		return row;
	}

	/**
	 * Updates each row within the grid such that it's x values are set to center the row in
	 * the grid.  Each row will be updated so that all its columns start at zero.  After that, 
	 * each column will be centered in the grid.
	 */
	public void centerRows() {

		List<Row<V>> rows = rows();
		int maxCol = columnCount(rows);
		for (Row<V> row : rows) {

			row = zeroRowColumns(row);

			int rowColumnCount = row.getColumnCount();
			if (rowColumnCount == maxCol) {
				continue; // already the full size; no need to center
			}

			int delta = maxCol - rowColumnCount;
			int offset = delta / 2;
			List<V> vertices = row.getVertices();
			for (V v : vertices) {
				if (v == null) {
					continue;
				}

				int oldCol = col(v);
				set(v, row.index, oldCol + offset);
			}

			row.dispose();
		}
	}

	private int maxColumnIndex(List<Row<V>> rows) {
		int maxCol = 0;
		for (Row<V> row : rows) {
			maxCol = Math.max(maxCol, row.getEndColumn());
		}
		return maxCol;
	}

	private int maxRowIndex(List<Row<V>> rows) {
		int maxRow = 0;
		for (Row<V> row : rows) {
			maxRow = Math.max(maxRow, row.index);
		}
		return maxRow;
	}

	private int columnCount(List<Row<V>> rows) {

		int maxCount = 0;
		for (Row<V> row : rows) {
			maxCount = Math.max(maxCount, row.getColumnCount());
		}
		return maxCount;
	}

//	private int rowCount(List<Row<V>> rows) {
//		int minRow = 0;
//		int maxRow = 0;
//		for (Row<V> row : rows) {
//			minRow = Math.min(minRow, row.index);
//			maxRow = Math.max(maxRow, row.index);
//		}
//		return (maxRow - minRow) + 1; // +1 for zero-based
//	}

	private Row<V> zeroRowColumns(Row<V> row) {

		int start = row.getStartColumn();
		int offset = -start;

		Row<V> updatedRow = new Row<>();
		updatedRow.index = row.index;
		for (V v : row.getVertices()) {
			int oldCol = col(v);
			int newCol = oldCol + offset;
			set(v, row.index, newCol);
			updatedRow.setColumn(v, newCol);
		}

		row.dispose();
		return updatedRow;
	}

	GridLocationMap<V, E> copy() {
		GridLocationMap<V, E> map = new GridLocationMap<>();

		map.vertexPoints = new HashMap<>();
		Set<Entry<V, Point>> entries = vertexPoints.entrySet();
		for (Entry<V, Point> entry : entries) {
			map.vertexPoints.put(entry.getKey(), (Point) entry.getValue().clone());
		}

		map.edgePoints = new HashMap<>();
		Set<Entry<E, List<Point>>> edgeEntries = edgePoints.entrySet();
		for (Entry<E, List<Point>> entry : edgeEntries) {

			List<Point> points = entry.getValue();
			List<Point> clonedPoints = new ArrayList<>(points.size());
			for (Point p : points) {
				clonedPoints.add((Point) p.clone());
			}

			map.edgePoints.put(entry.getKey(), clonedPoints);
		}

		return map;
	}

	public void dispose() {
		vertexPoints.clear();
		edgePoints.clear();
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[\n\tvertex points=" + vertexPoints +
			"\n\tedge points=" + edgePoints + "]";
	}

	/**
	 * Creates a string representation of this grid
	 * @return a string representation of this grid
	 */
	public String toStringGrid() {

		GridLocationMap<V, E> copy = copy();
		zeroAlignGrid(copy);

		List<Row<V>> rows = copy.rows();
		int columnCount = copy.maxColumnIndex(rows) + 1;
		int rowCount = copy.maxRowIndex(rows) + 1;

		Object[][] vGrid = new Object[rowCount][columnCount];
		for (Row<V> row : rows) {
			List<V> vertices = row.getVertices();
			for (V v : vertices) {
				vGrid[row.index][row.getColumn(v)] = v;
			}
		}

		StringBuilder buffy = new StringBuilder("\n");
		for (int row = 0; row < rowCount; row++) {
			for (int col = 0; col < columnCount; col++) {
				Object o = vGrid[row][col];
				buffy.append(' ');
				if (o == null) {
					buffy.append('-');
					//buffy.append(' ');
				}
				else {
					buffy.append('v');
				}
				buffy.append(' ');
			}
			buffy.append('\n');
		}

		return buffy.toString();
	}

	// moves all rows and columns as needed to convert the grid origin to 0,0
	private static <V, E> void zeroAlignGrid(GridLocationMap<V, E> grid) {

		int smallestColumnIndex = 0;
		int smallestRowIndex = 0;
		List<Row<V>> rows = grid.rows();
		for (Row<V> row : rows) {
			smallestRowIndex = Math.min(smallestRowIndex, row.index);
			smallestColumnIndex = Math.min(smallestColumnIndex, row.getStartColumn());
		}

		int globalColumnOffset = -smallestColumnIndex;
		int globalRowOffset = -smallestRowIndex;

		for (Row<V> row : rows) {

			List<V> vertices = row.getVertices();
			for (V v : vertices) {
				int oldCol = grid.col(v);
				int oldRow = grid.row(v);
				int newCol = globalColumnOffset + oldCol;
				int newRow = globalRowOffset + oldRow;
				grid.set(v, newRow, newCol);
			}
		}
	}
}
