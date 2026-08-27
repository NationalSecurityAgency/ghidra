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

import java.util.Objects;

/**
 * Simple class to return a row, column location.
 */
public class RowColLocation {
	protected int row;
	protected int col;
	private boolean isHidden;

	/**
	 * Constructs a new RowColLocation with the given row and column.
	 * @param row the row location
	 * @param col the column location
	 */
	public RowColLocation(int row, int col) {
		this.row = row;
		this.col = col;
		this.isHidden = false;
	}

	/**
	 * Constructs a new RowColLocation with the given row and column.
	 * @param row the row location
	 * @param col the column location
	 * @param isHidden true if the given location is replaced with ellipsis in the UI
	 */
	public RowColLocation(int row, int col, boolean isHidden) {
		this.row = row;
		this.col = col;
		this.isHidden = isHidden;
	}

	public int row() {
		return row;
	}

	public int col() {
		return col;
	}

	/**
	 * {@return true if this location is hidden, such as when the location is replaced by an ellipsis
	 * in the UI}
	 */
	public boolean isHidden() {
		return isHidden;
	}

	public RowColLocation withCol(int newColumn) {
		return new RowColLocation(row, newColumn, isHidden);
	}

	public RowColLocation withRow(int newRow) {
		return new RowColLocation(newRow, col, isHidden);
	}

	@Override
	public String toString() {
		return row + "," + col + (isHidden ? ", hidden" : "");
	}

	@Override
	public int hashCode() {
		return Objects.hash(row, col, isHidden);
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
		return row == loc.row && col == loc.col && isHidden == loc.isHidden;
	}
}
