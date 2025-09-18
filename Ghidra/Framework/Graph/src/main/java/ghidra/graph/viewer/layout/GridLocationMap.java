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

import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Stream;

import org.apache.commons.collections4.map.LazyMap;

/**
 * An object that maps vertices and edge articulation points to rows and columns in a grid. This
 * class is essentially a container that allows layout algorithms to store results as it lays
 * out vertices and edges in a virtual grid. Later, this information can be used in conjunction 
 * with vertex size information and padding information to transform these grid coordinates to
 * layout space coordinates.
 * <P>
 * This object also has methods for manipulating the grid such as shifting it up, down, left, right,
 * and merging in other GridLocationMaps
 * <P>
 * After building the grid using this class, clients can call {@link #rows()}, {@link #rowsMap()},
 * or {@link #columnsMap()} to get high-order objects that represent rows or columns.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class GridLocationMap<V, E> {

	protected Map<V, GridPoint> vertexPoints =
		LazyMap.lazyMap(new HashMap<V, GridPoint>(), v -> new GridPoint(0, 0));

	protected Map<E, List<GridPoint>> edgePoints = new HashMap<>();
	private GridBounds gridBounds = new GridBounds();
	// Tree based algorithms might want to track the location of the root node as it changes when
	// the grid is shifted or merged. Useful for determining the position of a parent node when
	// building bottom up.
	private GridPoint rootPoint;

	public GridLocationMap() {
		rootPoint = new GridPoint(0, 0);
	}

	/**
	 * Constructor that includes an initial "root" vertex.
	 * @param root the initial vertex
	 * @param row the row for the initial vertex
	 * @param col the column for the initial vertex. 
	 */
	public GridLocationMap(V root, int row, int col) {
		rootPoint = new GridPoint(row, col);
		set(root, new GridPoint(row, col));
	}

	/**
	 * Returns the column of the initial vertex in this grid.
	 * @return the column of the initial vertex in this grid
	 */
	public int getRootColumn() {
		return rootPoint.col;
	}

	/**
	 * Returns the row of the initial vertex in this grid.
	 * @return the row of the initial vertex in this grid
	 */
	public int getRootRow() {
		return rootPoint.row;
	}

	public Set<V> vertices() {
		return vertexPoints.keySet();
	}

	public Set<E> edges() {
		return edgePoints.keySet();
	}

	public Map<V, GridPoint> getVertexPoints() {
		return vertexPoints;
	}

	public void setArticulations(E edge, List<GridPoint> articulations) {
		edgePoints.put(edge, articulations);
		if (articulations != null) {
			for (GridPoint gridPoint : articulations) {
				gridBounds.update(gridPoint);
			}
		}
	}

	public List<GridPoint> getArticulations(E edge) {
		List<GridPoint> list = edgePoints.get(edge);
		if (list == null) {
			return Collections.emptyList();
		}
		return list;
	}

	public void row(V vertex, int row) {
		GridPoint gridPoint = vertexPoints.get(vertex);
		gridPoint.row = row;
		gridBounds.update(gridPoint);
	}

	public void col(V vertex, int col) {
		GridPoint gridPoint = vertexPoints.get(vertex);
		gridPoint.col = col;
		gridBounds.update(gridPoint);
	}

	public void set(V v, int row, int col) {
		set(v, new GridPoint(row, col));
	}

	public void set(V v, GridPoint gridPoint) {
		vertexPoints.put(v, gridPoint);
		gridBounds.update(gridPoint);
	}

	public int row(V vertex) {
		GridPoint gridPoint = vertexPoints.get(vertex);
		if (gridPoint != null) {
			return gridPoint.row;
		}
		return 0;
	}

	public int col(V vertex) {
		GridPoint gridPoint = vertexPoints.get(vertex);
		if (gridPoint != null) {
			return gridPoint.col;
		}
		return 0;
	}

	public GridPoint gridPoint(V vertex) {
		return vertexPoints.get(vertex);
	}

	/**
	 * Returns the rows in this grid, sorted by index (index can be negative)
	 * 
	 * @return the rows in this grid
	 */
	public List<Row<V>> rows() {
		Map<Integer, Row<V>> rowsByIndex = rowsMap();
		List<Row<V>> rows = new ArrayList<>(rowsByIndex.values());
		rows.sort((r1, r2) -> r1.index - r2.index);
		return rows;
	}

	/**
	 * Returns a mapping or row indexes to Row objects in this grid
	 * 
	 * @return the rows in this grid
	 */
	public Map<Integer, Row<V>> rowsMap() {
		Map<Integer, Row<V>> rowsByIndex = LazyMap.lazyMap(new HashMap<>(), r -> new Row<V>(r));

		Set<Entry<V, GridPoint>> entrySet = vertexPoints.entrySet();
		for (Entry<V, GridPoint> entry : entrySet) {
			V v = entry.getKey();
			GridPoint gridPoint = entry.getValue();
			int rowIndex = gridPoint.row;
			Row<V> row = rowsByIndex.get(rowIndex);
			row.setColumn(v, gridPoint.col);
		}
		return rowsByIndex;
	}

	/**
	 * Returns a mapping or column indexes to Column objects in this grid
	 * 
	 * @return the columns in this grid
	 */
	public Map<Integer, Column<V>> columnsMap() {
		Map<Integer, Column<V>> columnsMap =
			LazyMap.lazyMap(new HashMap<>(), c -> new Column<V>(c));

		Set<Entry<V, GridPoint>> entrySet = vertexPoints.entrySet();
		for (Entry<V, GridPoint> entry : entrySet) {
			V v = entry.getKey();
			GridPoint gridPoint = entry.getValue();
			int colIndex = gridPoint.col;
			Column<V> col = columnsMap.get(colIndex);
			col.setRow(v, gridPoint.row);
		}
		return columnsMap;
	}

	/**
	 * Updates each row within the grid such that it's column values are set to center the row in
	 * the grid.  Each row will be updated so that all its columns start at zero.  After that, 
	 * each column will be centered in the grid.
	 */
	public void centerRows() {
		zeroAlignGrid();
		GridRange[] vertexColumnRanges = getVertexColumnRanges();
		int maxRowWidth = getMaxRowWidth(vertexColumnRanges);

		for (GridPoint p : allPoints()) {
			GridRange range = vertexColumnRanges[p.row];
			int extraSpace = maxRowWidth - range.width();
			int shift = extraSpace / 2 - range.min;
			p.col += shift;
		}
	}

	private int getMaxRowWidth(GridRange[] vertexColumnRanges) {
		int maxWidth = 0;
		for (GridRange gridRange : vertexColumnRanges) {
			maxWidth = Math.max(maxWidth, gridRange.width());
		}
		return maxWidth;
	}

	/**
	 * Shifts the grid so that its first row and column are at 0.
	 */
	public void zeroAlignGrid() {
		shift(-gridBounds.minRow(), -gridBounds.minCol());
	}

	public void dispose() {
		vertexPoints.clear();
		edgePoints.clear();
	}

	/**
	 * Shifts the rows and columns for all points in this map by the given amount.
	 * @param rowShift the amount to shift the rows of each point
	 * @param colShift the amount to shift the columns of each point
	 */
	public void shift(int rowShift, int colShift) {
		if (rowShift == 0 && colShift == 0) {
			return;
		}

		for (GridPoint p : allPoints()) {
			p.row += rowShift;
			p.col += colShift;
		}
		rootPoint.row += rowShift;
		rootPoint.col += colShift;
		gridBounds.shift(rowShift, colShift);

	}

	/**
	 * Returns the number of rows in this grid map. Note that this includes empty rows
	 * starting at the 0 row. 
	 * @return the number of rows in this grid map
	 */
	public int height() {
		return gridBounds.maxRow() + 1;
	}

	/**
	 * Returns the number of columns in this grid map. Note that this includes empty columns 
	 * starting at the 0 column. 
	 * @return the number of columns in this grid map
	 */
	public int width() {
		return gridBounds.maxCol() + 1;
	}

	/**
	 * Returns the minimum/max column for all rows in the grid. This method is only defined for
	 * grids that have no negative rows. This is because the array returned will be 0 based, with
	 * the entry at index 0 containing the column bounds for row 0 and so on.
	 * @return the minimum/max column for all rows in the grid
	 * @throws IllegalStateException if this method is called on a grid with negative rows.
	 */
	public GridRange[] getVertexColumnRanges() {
		if (gridBounds.minRow() < 0) {
			throw new IllegalStateException(
				"getVertexColumnRanges not defined for grids with negative rows!");
		}
		GridRange[] rowRanges = new GridRange[height()];

		for (int i = 0; i < rowRanges.length; i++) {
			rowRanges[i] = new GridRange();
		}

		for (GridPoint p : vertexPoints.values()) {
			rowRanges[p.row].add(p.col);
		}
		return rowRanges;
	}

	/**
	 * Returns the minimum/max row for all columns in the grid. This method is only defined for
	 * grids that have no negative columns. This is because the array returned will be 0 based, with
	 * the entry at index 0 containing the row bounds for column 0 and so on.
	 * @return the minimum/max row for all columns in the grid
	 * @throws IllegalStateException if this method is called on a grid with negative rows.
	 */
	public GridRange[] getVertexRowRanges() {
		if (gridBounds.minCol() < 0) {
			throw new IllegalStateException(
				"getVertexColumnRanges not defined for grids with negative rows!");
		}
		GridRange[] colRanges = new GridRange[width()];

		for (int i = 0; i < colRanges.length; i++) {
			colRanges[i] = new GridRange();
		}

		for (GridPoint p : vertexPoints.values()) {
			colRanges[p.col].add(p.row);
		}
		return colRanges;
	}

	public boolean containsVertex(V v) {
		return vertexPoints.containsKey(v);
	}

	public boolean containsEdge(E e) {
		return edgePoints.containsKey(e);
	}

	/**
	 * Adds in the vertices and edges from another GridLocationMap with each point in the other
	 * grid map shifted by the given row and column amounts.
	 * @param other the other GridLocationMap to add to this one.
	 * @param rowShift the amount to shift the rows in the grid points from the other grid before
	 * adding them to this grid
	 * @param colShift the amount to shift the columns in the grid points from the other grid before
	 * adding them to this grid
	 */
	public void add(GridLocationMap<V, E> other, int rowShift, int colShift) {

		for (Entry<V, GridPoint> entry : other.vertexPoints.entrySet()) {
			V v = entry.getKey();
			GridPoint point = entry.getValue();
			set(v, new GridPoint(point.row + rowShift, point.col + colShift));
		}

		for (Entry<E, List<GridPoint>> entry : other.edgePoints.entrySet()) {
			E e = entry.getKey();
			List<GridPoint> points = entry.getValue();
			List<GridPoint> shiftedPoints = new ArrayList<>(points.size());
			for (GridPoint point : points) {
				shiftedPoints.add(new GridPoint(point.row + rowShift, point.col + colShift));
			}
			setArticulations(e, shiftedPoints);
		}
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
		int minRow = gridBounds.minRow();
		int minCol = gridBounds.minCol();
		if (minRow > 10 || minCol > 10) {
			GridLocationMap<V, E> copy = copy();
			copy.zeroAlignGrid();
			return "grid upper left (row,col) = (" + minRow + ", " + minCol + ")\n" +
				copy.toStringGrid();
		}

		String[][] vGrid = new String[height()][width()];

		for (Entry<V, GridPoint> entry : vertexPoints.entrySet()) {
			V v = entry.getKey();
			GridPoint p = entry.getValue();
			vGrid[p.row][p.col] = normalizeVertexName(v.toString());
		}
		StringBuilder buffy = new StringBuilder();
		buffy.append("\n");
		for (int row = 0; row < vGrid.length; row++) {
			for (int col = 0; col < vGrid[row].length; col++) {
				String name = vGrid[row][col];
				name = name == null ? ".       " : name;
				buffy.append(name);
				buffy.append("");
			}
			buffy.append("\n");
		}
		return buffy.toString();
	}

	private GridLocationMap<V, E> copy() {
		GridLocationMap<V, E> map = new GridLocationMap<>();
		map.rootPoint = new GridPoint(rootPoint.row, rootPoint.col);

		Set<Entry<V, GridPoint>> entries = vertexPoints.entrySet();
		for (Entry<V, GridPoint> entry : entries) {
			map.set(entry.getKey(), new GridPoint(entry.getValue()));
		}

		Set<Entry<E, List<GridPoint>>> edgeEntries = edgePoints.entrySet();
		for (Entry<E, List<GridPoint>> entry : edgeEntries) {
			List<GridPoint> points = entry.getValue();
			List<GridPoint> copy = new ArrayList<>(points.size());
			points.forEach(p -> copy.add(new GridPoint(p)));
			map.setArticulations(entry.getKey(), copy);
		}

		return map;
	}

	private String normalizeVertexName(String name) {
		if (name.length() > 8) {
			return name.substring(0, 8);
		}
		return name + "        ".substring(name.length());
	}

	private Iterable<GridPoint> allPoints() {
		Stream<GridPoint> vPoints = vertexPoints.values().stream();
		Stream<GridPoint> ePoints = edgePoints.values().stream().flatMap(l -> l.stream());
		Stream<GridPoint> streams = Stream.concat(vPoints, ePoints);
		return () -> streams.iterator();
	}

	public boolean containsPoint(GridPoint p) {
		return gridBounds.contains(p);
	}
}
