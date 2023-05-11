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

public class VariableRowHeightGridLayout implements LayoutManager {

	private int vgap;
	private int hgap;
	private final int columnCount;

	public VariableRowHeightGridLayout(int columnCount) {
		this(0, 0, columnCount);
	}

	/**
	 * Constructs a new PairLayout.
	 * @param vgap the gap (in pixels) between rows.
	 * @param hgap the gap (in pixels) between the two columns.
	 * @param columnCount the number of columns in this grid
	 */
	public VariableRowHeightGridLayout(int vgap, int hgap, int columnCount) {
		this.vgap = vgap;
		this.hgap = hgap;

		if (columnCount <= 0) {
			columnCount = 1;
		}

		this.columnCount = columnCount;
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

		int totalColumns = Math.min(columnCount, componentCount);
		int totalComponentWidth = getPreferredColumnWidth(parent) * totalColumns;
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

	private int getPreferredColumnWidth(Container parent) {
		int width = 0;
		int componentCount = parent.getComponentCount();
		for (int i = 0; i < componentCount; i++) {
			Component component = parent.getComponent(i);
			Dimension d = component.getPreferredSize();
			width = Math.max(width, d.width);
		}
		return width;
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
		int totalColumns = Math.min(columnCount, componentCount);
		int availableColumnWidth = (width - (columnCount - 1) * hgap) / totalColumns;
		int columnWidth = getColumnWidth(parent, availableColumnWidth);
		int y = insets.top;
		for (int i = 0; i < rowCount; i++) {
			int x = insets.left;
			int rowHeight = getRowHeight(parent, i);
			for (int j = 0; j < columnCount; j++) {
				int ordinal = i * columnCount + j;
				if (ordinal >= componentCount) {
					// this implies uneven components (can't fill the last row)
					break;
				}
				Component component = parent.getComponent(ordinal);
				component.setBounds(x, y, columnWidth, rowHeight);
				x += columnWidth + hgap;
			}
			y += rowHeight + vgap;
		}
	}

	private int getColumnWidth(Container parent, int availableColumnWidth) {
		return availableColumnWidth;
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
