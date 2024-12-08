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

/**
 * Tracks the minimum and maximum indexes for both rows and columns.
 */

public class GridBounds {
	private int minRow = 0;
	private int maxRow = 0;
	private int minCol = 0;
	private int maxCol = 0;

	/**
	 * Updates the bounds for the given GridPoint.
	 * @param p the gridPoint used to update the minimums and maximums
	 */
	public void update(GridPoint p) {
		minRow = Math.min(minRow, p.row);
		maxRow = Math.max(maxRow, p.row);
		minCol = Math.min(minCol, p.col);
		maxCol = Math.max(maxCol, p.col);
	}

	/**
	 * Shifts the columns bounds by the given amount
	 * @param rowShift the amount to shift the row bounds.
	 * @param colShift the amount to shift the column bounds.
	 * @throws IllegalArgumentException if the shift would make the minimum column negative
	 */
	public void shift(int rowShift, int colShift) {
		minCol += colShift;
		maxCol += colShift;
		minRow += rowShift;
		maxRow += rowShift;
	}

	@Override
	public String toString() {
		StringBuilder buffy = new StringBuilder();
		buffy.append("Grid Bounds: ");
		if (minRow == Integer.MAX_VALUE) {
			return "Empty";
		}

		buffy.append("rows: ").append(minRow).append(" -> ").append(maxRow);
		buffy.append(",  ");
		buffy.append("cols: ").append(minCol).append(" -> ").append(maxCol);
		return buffy.toString();
	}

	public int maxCol() {
		return maxCol;
	}

	public int minCol() {
		// handle case when grid is empty
		if (minCol > maxCol) {
			return 0;
		}
		return minCol;
	}

	public int maxRow() {
		return maxRow;
	}

	public int minRow() {
		// handle case when grid is empty
		if (minRow > maxRow) {
			return 0;
		}
		return minRow;
	}

	public boolean contains(GridPoint p) {
		if (p.row < minRow || p.row > maxRow) {
			return false;
		}
		if (p.col < minCol || p.col > maxCol) {
			return false;
		}
		return true;
	}

}
