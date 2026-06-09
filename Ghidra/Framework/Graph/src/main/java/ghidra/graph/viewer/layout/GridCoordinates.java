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

/**
 * Tracks the mapping of grid coordinates (rows, columns) to space coordinates (x, y)
 */
public class GridCoordinates {
	private int[] rowStarts;
	private int[] colStarts;

	/**
	 * Constructor
	 * @param rowCoordinates an array containing the y locations for all rows in a grid
	 * @param columnCoordinates an array containing the x locations for all columns in a grid
	 */
	public GridCoordinates(int[] rowCoordinates, int[] columnCoordinates) {
		rowStarts = rowCoordinates;
		colStarts = columnCoordinates;
	}

	/**
	 * Returns the x value for a given column.
	 * @param col the column index in the grid
	 * @return the x coordinate assigned to the given column index
	 */
	public int x(int col) {
		return colStarts[col];
	}

	/**
	 * Returns the y value for a given row.
	 * @param row the row index in the grid
	 * @return the y coordinate assigned to the given row index
	 */
	public int y(int row) {
		return rowStarts[row];
	}

	/**
	 * Returns the total bounds for the grid
	 * @return the total bounds for the grid
	 */
	public Rectangle getBounds() {
		return new Rectangle(0, 0, colStarts[colStarts.length - 1],
			rowStarts[rowStarts.length - 1]);
	}

	/**
	 * returns the number of rows in the grid.
	 * @return the number of rows in the grid
	 */
	public int rowCount() {
		return rowStarts.length;
	}

	/**
	 * returns the number of columns in the grid.
	 * @return the number of columns in the grid
	 */
	public int columnCount() {
		return colStarts.length;
	}
}
