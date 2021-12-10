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
package docking.widgets.fieldpanel.support;

/**
 * Simple class to return a row, column location.
 */
public class RowColLocation {
	protected int row;
	protected int col;

	/**
	 * Constructs a new RowColLocation with the given row and column.
	 * @param row the row location
	 * @param col the column location
	 */
	public RowColLocation(int row, int col) {
		this.row = row;
		this.col = col;
	}

	public int row() {
		return row;
	}

	public int col() {
		return col;
	}

	public RowColLocation withCol(int newColumn) {
		return new RowColLocation(row, newColumn);
	}

	public RowColLocation withRow(int newRow) {
		return new RowColLocation(newRow, col);
	}

	@Override
	public String toString() {
		return row + "," + col;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + col;
		result = prime * result + row;
		return result;
	}

	@Override
	public boolean equals(Object object) {
		if (object == null) {
			return false;
		}

		if (!getClass().equals(object.getClass())) {
			return false;
		}

		RowColLocation loc = (RowColLocation) object;
		return (row == loc.row) && (col == loc.col);
	}
}
