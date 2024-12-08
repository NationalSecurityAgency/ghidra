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

import java.awt.Rectangle;
import java.awt.Shape;
import java.util.*;
import java.util.Map.Entry;

import com.google.common.base.Function;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A class that holds row and column data for each vertex and edge.  
 * 
 * <P> This class will take in a {@link GridLocationMap}, which is comprised of grid index 
 * values, not layout space points.  Then, the grid values will be used to calculate 
 * offsets and size for each row and column. Each row has a y location and a height; each 
 * column has an x location and a width. The height and width are uniform in size across 
 * all rows and columns, based upon the tallest and widest vertex in the graph. 
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class LayoutLocationMap<V, E> {

	private int numRows;
	private int numColumns;

	private TreeMap<Integer, Row<V>> rowsByIndex = new TreeMap<>();
	private TreeMap<Integer, Column<V>> columnsByIndex = new TreeMap<>();

	private boolean isCondensed = false;
	private GridLocationMap<V, E> gridLocations;

	public LayoutLocationMap(GridLocationMap<V, E> gridLocations, Function<V, Shape> transformer,
			boolean isCondensed, TaskMonitor monitor) throws CancelledException {
		this.isCondensed = isCondensed;
		this.gridLocations = gridLocations;

		Set<V> vertices = gridLocations.vertices();
		numRows = gridLocations.height();
		numColumns = gridLocations.width();

		initializeLayoutLocations(transformer, vertices, monitor);
	}

	public void dispose() {
		rowsByIndex.clear();
		columnsByIndex.clear();
	}

	public int getRowCount() {
		return numRows;
	}

	public int getColumnCount() {
		return numColumns;
	}

	public Column<V> col(V v) {
		Integer col = gridLocations.col(v);
		return doGetColumn(col);
	}

	public Column<V> col(int gridX) {
		return doGetColumn(gridX);
	}

	public Column<V> getColumnContaining(int x) {
		Column<V> column = null;
		Collection<Column<V>> values = columnsByIndex.values();
		for (Column<V> nextColumn : values) {
			if (x < nextColumn.x) {
				return column;
			}
			column = nextColumn;
		}
		return column;
	}

	private Column<V> doGetColumn(int index) {
		Column<V> column = columnsByIndex.get(index);
		if (column == null) {
			column = new Column<>(index);
			columnsByIndex.put(index, column);
		}
		return column;
	}

	/**
	 * Returns the columns in this location map, sorted from lowest index to highest 
	 * 
	 * @return the columns in this location map, sorted from lowest index to highest
	 */
	public Collection<Column<V>> columns() {
		List<Column<V>> result = new ArrayList<>();
		Collection<Column<V>> values = columnsByIndex.values();
		for (Column<V> column : values) {
			result.add(column);
		}
		return result;
	}

	/**
	 * Returns the rows in this location map, sorted from lowest index to highest 
	 * 
	 * @return the rows in this location map, sorted from lowest index to highest
	 */
	public Collection<Row<V>> rows() {
		List<Row<V>> results = new ArrayList<>();
		Collection<Row<V>> values = rowsByIndex.values();
		for (Row<V> row : values) {
			results.add(row);
		}
		return results;
	}

	public Column<V> lastColumn() {

		Entry<Integer, Column<V>> lastEntry = columnsByIndex.lastEntry();
		if (lastEntry == null) {
			return null;
		}
		return lastEntry.getValue();
	}

	public Column<V> nextColumn(Column<V> column) {
		Column<V> nextColumn = doGetColumn(column.index + 1);
		if (!nextColumn.isInitialized()) {
			// last column?
			nextColumn.x = column.x + column.getPaddedWidth(isCondensed);
		}
		return nextColumn;
	}

	public List<GridPoint> articulations(E e) {
		return gridLocations.getArticulations(e);
	}

	public Row<V> row(V v) {
		int row = gridLocations.row(v);
		return doGetRow(row);
	}

	public Row<V> lastRow() {

		Entry<Integer, Row<V>> lastEntry = rowsByIndex.lastEntry();
		if (lastEntry == null) {
			return null;
		}
		return lastEntry.getValue();
	}

	public Row<V> row(int gridY) {
		return doGetRow(gridY);
	}

	private Row<V> doGetRow(int index) {
		Row<V> row = rowsByIndex.get(index);
		if (row == null) {
			row = new Row<>(index);
			rowsByIndex.put(index, row);
		}
		return row;
	}

	public int gridX(Column col) {
		return col.index;
	}

	public int gridY(Row<V> row) {
		return row.index;
	}

	public List<Integer> getRowOffsets() {
		ArrayList<Integer> list = new ArrayList<>();
		for (Row<V> row : rowsByIndex.values()) {
			list.add(row.y);
		}
		return list;
	}

	public List<Integer> getColOffsets() {
		ArrayList<Integer> list = new ArrayList<>();
		for (Column<V> column : columnsByIndex.values()) {
			list.add(column.x);
		}
		return list;
	}

	public boolean isCondensed() {
		return isCondensed;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[\n\trows=" + rowsByIndex + "\n\tcolumns=" +
			columnsByIndex + "]";
	}

	public GridCoordinates getGridCoordinates() {
		Row<?> lastRow = lastRow();
		Column<?> lastColumn = lastColumn();
		if (lastRow == null || lastColumn == null) {
			return new GridCoordinates(new int[0], new int[0]);
		}

		// add 1 to compute a row y value and a column x value for closing the grid
		int[] rowStarts = new int[lastRow.index + 1];
		int[] colStarts = new int[lastColumn.index + 1];

		for (Row<?> row : rowsByIndex.values()) {
			rowStarts[row.index] = row.y;
		}
		for (Column<?> col : columnsByIndex.values()) {
			colStarts[col.index] = col.x;
		}

		// Give any empty rows or columns the coordinate of the row or column that precedes it 
		// since it takes no space. (Otherwise all the empty row or column labels would overwrite
		// themselves at the 0 row or 0 column.
		for (int row = 1; row < rowStarts.length; row++) {
			if (rowStarts[row] == 0) {
				rowStarts[row] = rowStarts[row - 1];
			}
		}
		for (int col = 1; col < colStarts.length; col++) {
			if (colStarts[col] == 0) {
				colStarts[col] = colStarts[col - 1];
			}
		}

		// close the grid
		rowStarts[rowStarts.length - 1] = lastRow.y + lastRow.getPaddedHeight(isCondensed);
		colStarts[colStarts.length - 1] = lastColumn.x + lastColumn.getPaddedWidth(isCondensed);

		return new GridCoordinates(rowStarts, colStarts);

	}

//==================================================================================================
// Initialization Code
//==================================================================================================

	private void initializeLayoutLocations(Function<V, Shape> transformer, Collection<V> vertices,
			TaskMonitor monitor) throws CancelledException {

		// create this class's rows from the grid
		Collection<Row<V>> gridRows = gridLocations.rowsMap().values();
		for (Row<V> row : gridRows) {
			rowsByIndex.put(row.index, row);
		}

		//
		// Go through all the columns and rows looking for candidate vertices in order to 
		// find the minimum row height and column width for each row and column (which is the
		// largest values found).
		//
		for (V vertex : vertices) {
			monitor.checkCancelled();

			Row<V> row = row(vertex);
			Column<V> column = col(vertex);
			Shape shape = transformer.apply(vertex);
			Rectangle bounds = shape.getBounds();
			if (bounds.width > column.width) {
				column.width = bounds.width;
			}
			if (bounds.height > row.height) {
				row.height = bounds.height;
			}
		}

		//
		// Calculate offset locations (y values) from row heights (plus any padding)
		//
		int offset = 0;
		int n = getRowCount();
		for (int i = 0; i < n; i++) {
			monitor.checkCancelled();

			Row<V> row = row(i);
			row.y = offset;
			offset += row.getPaddedHeight(isCondensed);
		}

		//
		// Calculate offset locations (x values) from row widths (plus any padding)
		//

		//
		// TODO instead of looping by index, we could loop by Column, using a double index
		//      value which is the index, followed by an offset, so, 3.25 would be column
		//      3, pushed .25% of column 3's width to the right; -3.25 would be column 3, pulled
		//      .25% of column 3's width to the left.  This allows us to control the offset of
		//      the vertex within its column.
		//

		offset = 0;
		n = getColumnCount();
		for (int i = 0; i < n; i++) {
			monitor.checkCancelled();

			Column<V> column = col(i);
			column.x = offset;
			offset += column.getPaddedWidth(isCondensed);
		}
	}

}
