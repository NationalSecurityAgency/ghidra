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
package ghidra.util.layout;

import java.awt.*;

/**
 * <CODE>MaximizeSpecificColumnGridLayout</CODE> is a row oriented grid type of layout.
 * It lays out rows of information in a table format using a specific number of columns. 
 * Components are added left to right and top to bottom. The table will try to give each column
 * the width that is necessary to display the longest item in that column. The columns with the 
 * widest desired component size will get reduced first if there isn't enough room. 
 * The maximizeColumn(int) method allows you to indicate that you want to try to keep the size
 * of a column at the preferred size of the widest component in that column as the parent 
 * container component is resized. Any column that has been maximized won't shrink until the 
 * non-maximized windows are reduced to a width of zero.
 * The intent is that all non-maximized columns will shrink from largest to smallest so that
 * they all will become zero width together at which point the maximized columns will begin 
 * shrinking in a similar manner.
 */
public class MaximizeSpecificColumnGridLayout implements LayoutManager {

	private int vgap;
	private int hgap;
	private final int columnCount;
	private boolean[] maximizedColumns;

	/**
	 * Constructor with no gap between rows or columns.
	 * @param columnCount the number of columns in this grid
	 */
	public MaximizeSpecificColumnGridLayout(int columnCount) {
		this(0, 0, columnCount);
	}

	/**
	 * Constructor.
	 * @param vgap the gap (in pixels) between rows.
	 * @param hgap the gap (in pixels) between the two columns.
	 * @param columnCount the number of columns in this grid
	 */
	public MaximizeSpecificColumnGridLayout(int vgap, int hgap, int columnCount) {
		this.vgap = vgap;
		this.hgap = hgap;

		if (columnCount <= 0) {
			columnCount = 1;
		}

		this.columnCount = columnCount;
		maximizedColumns = new boolean[columnCount];
	}

	/**
	 * Allows you to indicate that you want to try to keep the size of a column at the preferred 
	 * size of the widest component in that column as the parent container component is resized. 
	 * Any column that has been maximized won't shrink until the non-maximized windows are reduced 
	 * to a width of zero.
	 * @param column the number (0 based) of the column to keep maximized.
	 */
	public void maximizeColumn(int column) {
		maximizedColumns[column] = true;
	}

	@Override
	public Dimension preferredLayoutSize(Container parent) {
		int componentCount = parent.getComponentCount();
		int rowCount = (componentCount + (columnCount - 1)) / columnCount;
		Insets insets = parent.getInsets();
		Dimension d = new Dimension(0, 0);
		int totalComponentHeight = 0;
		for (int i = 0; i < rowCount; i++) {
			totalComponentHeight += getRowHeight(parent, i);
		}
		int[] desiredColumnWidths = getDesiredColumnWidths(parent);

		int totalComponentWidth = getTotalWidth(desiredColumnWidths);
		d.width = totalComponentWidth + hgap * (columnCount - 1) + insets.left + insets.right;
		d.height = totalComponentHeight + vgap * (rowCount - 1) + insets.top + insets.bottom;
		return d;
	}

	private int getRowHeight(Container parent, int row) {
		int rowHeight = 0;
		int componentCount = parent.getComponentCount();
		for (int i = 0; i < columnCount; i++) {
			int ordinal = row * columnCount + i;
			if (ordinal >= componentCount) {
				// this implies uneven components (can't fill the last row)
				return rowHeight;
			}

			Component component = parent.getComponent(ordinal);
			Dimension d = component.getPreferredSize();
			rowHeight = Math.max(rowHeight, d.height);
		}
		return rowHeight;
	}

	@Override
	public Dimension minimumLayoutSize(Container parent) {
		return preferredLayoutSize(parent);
	}

	@Override
	public void layoutContainer(Container parent) {
		int componentCount = parent.getComponentCount();
		int rowCount = (componentCount + (columnCount - 1)) / columnCount;
		Dimension d = parent.getSize();
		Insets insets = parent.getInsets();
		int width = d.width - (insets.left + insets.right);
		int[] desiredColumnWidths = getDesiredColumnWidths(parent);
		int totalDesiredWidth = getTotalWidth(desiredColumnWidths);
		int offset = (totalDesiredWidth < width) ? ((width - totalDesiredWidth) / 2) : 0;
		int[] computedColumnWidths = getComputedColumnWidths(width, desiredColumnWidths);
		int y = insets.top;
		for (int i = 0; i < rowCount; i++) {
			int x = insets.left + offset;
			int rowHeight = getRowHeight(parent, i);
			for (int j = 0; j < columnCount; j++) {
				int ordinal = i * columnCount + j;
				if (ordinal >= componentCount) {
					// this implies uneven components (can't fill the last row)
					break;
				}
				Component component = parent.getComponent(ordinal);
				component.setBounds(x, y, computedColumnWidths[j], rowHeight);
				x += computedColumnWidths[j] + hgap;
			}
			y += rowHeight + vgap;
		}
	}

	private int getTotalWidth(int[] individualWidths) {
		int total = 0;
		for (int i = 0; i < individualWidths.length; i++) {
			total += individualWidths[i];
		}
		return total;
	}

	private int[] getComputedColumnWidths(int width, int[] desiredColumnWidths) {
		int[] computedColumnWidths = new int[desiredColumnWidths.length];
		int remainingColumnCount = desiredColumnWidths.length;
		int remainingWidth = width - (hgap * (desiredColumnWidths.length - 1)); // Width of columns only, excluding gaps.
		int maximizedCount = getMaximizedCount();
		if (maximizedCount > 0) {
			int desiredMaximizedWidth = getDesiredMaximizedWidth(desiredColumnWidths);
			if (desiredMaximizedWidth >= width) {
				// Maximized will consume entire width, so divide it up among maximized.
				int remainingMaximizedWidth = width;
				int averageMaximizedWidth = remainingMaximizedWidth / maximizedCount;
				int remainingMaximizedCount = maximizedCount;
				boolean foundOne = true;
				while (foundOne) {
					foundOne = false;
					for (int i = 0; i < computedColumnWidths.length; i++) {
						if ((maximizedColumns[i] == true) && (computedColumnWidths[i] == 0)) {
							// This is a maximized that doesn't yet have a computed width.
							if (desiredColumnWidths[i] < averageMaximizedWidth) {
								computedColumnWidths[i] = desiredColumnWidths[i];
								remainingMaximizedWidth -= computedColumnWidths[i];
								remainingMaximizedCount--;
								foundOne = true;
							}
						}
					}
					averageMaximizedWidth = (remainingMaximizedCount > 0)
							? (remainingMaximizedWidth / remainingMaximizedCount)
							: 0;
				}

				// Now just divide up whatever width remains among whatever maximized columns remain.
				for (int i = 0; i < computedColumnWidths.length; i++) {
					if ((maximizedColumns[i] == true) && (computedColumnWidths[i] == 0)) {
						// This is a maximized that doesn't yet have a computed width.
						computedColumnWidths[i] = averageMaximizedWidth;
						remainingMaximizedWidth -= computedColumnWidths[i];
						remainingMaximizedCount--;
					}
				}
				return computedColumnWidths;
			}

			// Each maximized gets width it wants and the rest will be divided.
			for (int i = 0; i < desiredColumnWidths.length; i++) {
				if (maximizedColumns[i] == true) {
					computedColumnWidths[i] = desiredColumnWidths[i];
					remainingWidth -= computedColumnWidths[i];
					remainingColumnCount--;
				}
			}
		}

		int averageColumnWidth =
			(remainingColumnCount > 0) ? (remainingWidth / remainingColumnCount) : 0;
		boolean foundOne = true;
		while (foundOne) {
			foundOne = false;
			for (int i = 0; i < computedColumnWidths.length; i++) {
				if (computedColumnWidths[i] == 0) {
					if (desiredColumnWidths[i] < averageColumnWidth) {
						computedColumnWidths[i] = desiredColumnWidths[i];
						remainingWidth -= computedColumnWidths[i];
						remainingColumnCount--;
						foundOne = true;
					}
				}
			}
			averageColumnWidth =
				(remainingColumnCount > 0) ? (remainingWidth / remainingColumnCount) : 0;
		}

		// Now just divide up whatever width remains among whatever columns remain.
		for (int i = 0; i < computedColumnWidths.length; i++) {
			if (computedColumnWidths[i] == 0) {
				computedColumnWidths[i] = averageColumnWidth;
			}
		}
		return computedColumnWidths;
	}

	private int getMaximizedCount() {
		int count = 0;
		for (int i = 0; i < maximizedColumns.length; i++) {
			if (maximizedColumns[i] == true) {
				count++;
			}
		}
		return count;
	}

	private int[] getDesiredColumnWidths(Container parent) {
		int[] columnWidths = new int[columnCount];
		int componentCount = parent.getComponentCount();
		int rowCount = (componentCount + (columnCount - 1)) / columnCount;
		for (int i = 0; i < rowCount; i++) {
			for (int j = 0; j < columnCount; j++) {
				int ordinal = i * columnCount + j;
				if (ordinal >= componentCount) {
					// this implies uneven components (can't fill the last row)
					break;
				}
				Component component = parent.getComponent(ordinal);
				columnWidths[j] = Math.max(columnWidths[j], component.getPreferredSize().width);
			}
		}
		return columnWidths;
	}

	private int getDesiredMaximizedWidth(int[] desiredWidths) {
		int width = 0;
		for (int i = 0; i < desiredWidths.length; i++) {
			if (maximizedColumns[i] == true) {
				width += desiredWidths[i];
			}
		}
		return width;
	}

	@Override
	public void addLayoutComponent(String name, Component comp) {
		// ignore
	}

	@Override
	public void removeLayoutComponent(Component comp) {
		// ignore
	}
}
