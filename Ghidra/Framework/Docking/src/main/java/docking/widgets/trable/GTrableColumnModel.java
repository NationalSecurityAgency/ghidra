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
package docking.widgets.trable;

import java.util.ArrayList;
import java.util.List;

/**
 * Abstract base class for {@link GTrable} column models
 *
 * @param <T> the row object type
 */
public abstract class GTrableColumnModel<T> {
	private List<GTrableColumn<T, ?>> columns = new ArrayList<>();
	private int totalWidth;

	public GTrableColumnModel() {
		reloadColumns();
	}

	/**
	 * {@return the number of columns in this model.}
	 */
	public int getColumnCount() {
		return columns.size();
	}

	/**
	 * {@return the column object for the given column index.}
	 * @param column the index of the column
	 */
	public GTrableColumn<T, ?> getColumn(int column) {
		return columns.get(column);
	}

	/**
	 * {@return the preferred width of the model which is the sum of the preferred widths of each
	 * column.}
	 */
	public int getPreferredWidth() {
		int preferredWidth = 0;
		for (GTrableColumn<T, ?> column : columns) {
			preferredWidth += column.getPreferredWidth();
		}
		return preferredWidth;
	}

	protected int computeWidth() {
		int width = 0;
		for (GTrableColumn<T, ?> column : columns) {
			width += column.getWidth();
		}
		return width;
	}

	protected void reloadColumns() {
		columns.clear();
		populateColumns(columns);
		computeColumnStarts();
		totalWidth = computeWidth();

	}

	/**
	 * Subclasses implement this method to define the columns for this model.
	 * @param columnList a list to populate with column objects
	 */
	protected abstract void populateColumns(List<GTrableColumn<T, ?>> columnList);

	protected void removeAllColumns() {
		columns.removeAll(columns);
		totalWidth = 0;
	}

	protected int getWidth() {
		return totalWidth;
	}

	protected int getIndex(int x) {
		for (int i = columns.size() - 1; i >= 0; i--) {
			GTrableColumn<T, ?> column = columns.get(i);
			if (x >= column.getStartX()) {
				return i;
			}
		}
		return 0;
	}

	protected void setWidth(int newWidth) {
		int diff = newWidth - totalWidth;
		if (diff == 0) {
			return;
		}
		if (diff > 0) {
			int amount = growLeftPreferred(columns.size() - 1, diff);
			growLeft(columns.size() - 1, amount);
		}
		else {
			shrinkLeft(columns.size() - 1, -diff);
		}
		computeColumnStarts();
	}

	void moveColumnStart(int columnIndex, int x) {
		GTrableColumn<T, ?> column = columns.get(columnIndex);
		int currentStartX = column.getStartX();
		int diff = x - currentStartX;
		if (diff > 0 && canGrowLeft(columnIndex - 1)) {
			int actualAmount = shrinkRight(columnIndex, diff);
			growLeft(columnIndex - 1, actualAmount);
		}
		else if (diff < 0 && canGrowRight(columnIndex)) {
			int actualAmount = shrinkLeft(columnIndex - 1, -diff);
			growRight(columnIndex, actualAmount);
		}
		computeColumnStarts();
	}

	private boolean canGrowLeft(int index) {
		return canGrow(0, index);
	}

	private boolean canGrowRight(int index) {
		return canGrow(index, columns.size() - 1);
	}

	private boolean canGrow(int index1, int index2) {
		for (int i = index1; i <= index2; i++) {
			if (columns.get(i).isResizable()) {
				return true;
			}
		}
		return false;
	}

	private void computeColumnStarts() {
		int x = 0;
		for (int i = 0; i < columns.size(); i++) {
			GTrableColumn<T, ?> column = columns.get(i);
			column.setStartX(x);
			int width = column.getWidth();
			x += width;
		}
		totalWidth = x;
		modelColumnsChaged();
	}

	protected void modelColumnsChaged() {
		// subclasses can override if they need to react to changes in the column positions or
		// sizes
	}

	private void growRight(int columnIndex, int amount) {
		for (int i = columnIndex; i < columns.size(); i++) {
			GTrableColumn<T, ?> column = columns.get(i);
			if (column.isResizable()) {
				column.setWidth(column.getWidth() + amount);
				return;
			}
		}
	}

	private void growLeft(int columnIndex, int amount) {
		for (int i = columnIndex; i >= 0; i--) {
			GTrableColumn<T, ?> column = columns.get(i);
			if (column.isResizable()) {
				column.setWidth(column.getWidth() + amount);
				return;
			}
		}
	}

	private int growLeftPreferred(int columnIndex, int amount) {
		for (int i = columnIndex; i >= 0 && amount > 0; i--) {
			GTrableColumn<T, ?> column = columns.get(i);
			if (!column.isResizable()) {
				continue;
			}
			int width = column.getWidth();
			int preferredWidth = column.getPreferredWidth();
			if (width < preferredWidth) {
				int adjustment = Math.min(amount, preferredWidth - width);
				column.setWidth(width + adjustment);
				amount -= adjustment;
			}
		}
		return amount;
	}

	private int growRightPreferred(int columnIndex, int amount) {
		for (int i = columnIndex; i < columns.size() && amount > 0; i++) {
			GTrableColumn<T, ?> column = columns.get(i);
			if (!column.isResizable()) {
				continue;
			}
			int width = column.getWidth();
			int preferredWidth = column.getPreferredWidth();
			if (width < preferredWidth) {
				int adjustment = Math.min(amount, preferredWidth - width);
				column.setWidth(width + adjustment);
				amount -= adjustment;
			}
		}
		return amount;
	}

	private int shrinkLeft(int columnIndex, int amount) {
		int remainingAmount = amount;
		for (int i = columnIndex; i >= 0 && remainingAmount > 0; i--) {
			remainingAmount -= shrinkColumn(i, remainingAmount);
		}
		return amount - remainingAmount;
	}

	private int shrinkRight(int columnIndex, int amount) {
		int remainingAmount = amount;
		for (int i = columnIndex; i < columns.size() && remainingAmount > 0; i++) {
			remainingAmount -= shrinkColumn(i, remainingAmount);
		}
		return amount - remainingAmount;
	}

	private int shrinkColumn(int columnIndex, int amount) {
		GTrableColumn<T, ?> column = columns.get(columnIndex);
		if (!column.isResizable()) {
			return 0;
		}
		int currentWidth = column.getWidth();
		int minWidth = column.getMinWidth();

		if (currentWidth >= minWidth + amount) {
			column.setWidth(currentWidth - amount);
			return amount;
		}
		column.setWidth(minWidth);
		return currentWidth - minWidth;
	}

}
