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
package ghidra.app.plugin.core.compositeeditor;

import java.awt.*;

import javax.swing.*;
import javax.swing.border.AbstractBorder;
import javax.swing.border.Border;
import javax.swing.table.TableCellRenderer;

/**
 */
public class DndTableCellRenderer implements TableCellRenderer {
	private int rowForFeedback = -1;
	private int rangeMin = -1;
	private int rangeMax = -1; // I believe this is inclusive
	private boolean inserting = false;

	private TableCellRenderer orig;

	private DndBorder border;
	private JTable table;

	public DndTableCellRenderer(TableCellRenderer orig, JTable table) {
		this.orig = orig;
		this.table = table;
		this.border = new DndBorder(0, 2, table.getSelectionBackground(), null);
	}

	public static class DndBorder extends AbstractBorder {
		private static final long serialVersionUID = 1L;
		private int borders;
		private int thickness;
		private Color color;
		private Border under;

		public static final int TOP = 1;
		public static final int RIGHT = 2;
		public static final int BOTTOM = 4;
		public static final int LEFT = 8;
		public static final int ALL = 15;

		public DndBorder(int borders, int thickness, Color color, Border under) {
			this.borders = borders;
			this.thickness = thickness;
			this.color = color;
			this.under = under;
		}

		@Override
		public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
			if (under != null) {
				under.paintBorder(c, g, x, y, width, height);
			}
			Graphics g2 = g.create();
			g2.setColor(color);
			if ((borders & TOP) == TOP) {
				g2.fillRect(x, y, width, thickness);
			}
			if ((borders & RIGHT) == RIGHT) {
				g2.fillRect(x + width - thickness, y, thickness, height);
			}
			if ((borders & BOTTOM) == BOTTOM) {
				g2.fillRect(x, y + height - thickness, width, thickness);
			}
			if ((borders & LEFT) == LEFT) {
				g2.fillRect(x, y, thickness, height);
			}
			g2.dispose();
		}

		@Override
		public Insets getBorderInsets(Component c) {
			if (under != null) {
				Insets result = under.getBorderInsets(c);
				return result;
			}
			throw new IllegalStateException("Must set under border");
		}

		@Override
		public Insets getBorderInsets(Component c, Insets insets) {
			if (under == null) {
				throw new IllegalStateException("Must set under border");
			}
			if (under instanceof AbstractBorder) {
				// Repeat the sin from JComponent.java:1847 (OpenJDK-1.8.0_25)
				// that necessitate this method in the first place...
				return ((AbstractBorder) under).getBorderInsets(c, insets);
			}
			Insets temp = under.getBorderInsets(c);
			insets.top = temp.top;
			insets.left = temp.left;
			insets.bottom = temp.bottom;
			insets.right = temp.right;
			return insets;
		}

		public void addBorders(int border) {
			borders |= border;
		}

		public void delBorders(int border) {
			borders &= ~border;
		}

		public void clrBorders() {
			borders = 0;
		}

		public void setUnderBorder(Border under) {
			this.under = under;
		}

		public Border getUnderBorder() {
			return under;
		}

		@Override
		public boolean isBorderOpaque() {
			return true;
		}

		public Color getColor() {
			return color;
		}

		public void setColor(Color color) {
			this.color = color;
		}
	}

	@Override
	public Component getTableCellRendererComponent(JTable myTable, Object value,
			boolean isSelected, boolean hasFocus, int row, int column) {
		JComponent c =
			(JComponent) orig.getTableCellRendererComponent(myTable, value, isSelected, hasFocus,
				row, column);
		Border origBorder = c.getBorder();
		if (origBorder instanceof DndBorder) {
			origBorder = ((DndBorder) origBorder).getUnderBorder();
		}
		border.setUnderBorder(origBorder);
		border.clrBorders();
		if (isSelected) {
			if (inSameSelectionBlock(row)) {
				if (column == 0 && !inserting) {
					border.addBorders(DndBorder.LEFT);
				}
				if (column == myTable.getColumnCount() - 1 && !inserting) {
					border.addBorders(DndBorder.RIGHT);
				}
				if (row == rangeMin) {
					border.addBorders(DndBorder.TOP);
				}
				if (row == rangeMax && !inserting) {
					border.addBorders(DndBorder.BOTTOM);
				}
				c.setBorder(border);
			}
			else {
				c.setBorder(origBorder);
			}
		}
		else {
			if (row == rowForFeedback) {
				border.addBorders(DndBorder.TOP);
				if (!inserting) {
					border.addBorders(DndBorder.BOTTOM);
				}
				if (column == 0 && !inserting) {
					border.addBorders(DndBorder.LEFT);
				}
				if (column == myTable.getColumnCount() - 1 & !inserting) {
					border.addBorders(DndBorder.RIGHT);
				}
				c.setBorder(border);
			}
			else {
				c.setBorder(origBorder);
			}
		}

		return c;
	}

	private boolean inSameSelectionBlock(int row) {
		if (rowForFeedback == -1) {
			return false;
		}
		return ((row >= rangeMin) && (row <= rangeMax));
	}

	public Color getBorderColor() {
		return border.getColor();
	}

	public void setBorderColor(Color color) {
		border.setColor(color);
	}

	/**
	 * @param inserting true indicates that only the top of the row is highlighted for feedback.
	 * false indicates that the entire selection should be bordered on all sides.
	 */
	public void selectRange(boolean inserting) {
		this.inserting = inserting;
		int tmpRow = rowForFeedback;
		rowForFeedback = -1;
		rangeMin = -1;
		rangeMax = -1;
		setRowForFeedback(tmpRow);
	}

	public boolean setRowForFeedback(int row) {
		if (rowForFeedback == row) {
			return false;
		}
		rowForFeedback = row;
		rangeMin = -1;
		rangeMax = -1;
		if (row == -1) {
			return true;
		}
		ListSelectionModel model = table.getSelectionModel();
		if (!model.isSelectedIndex(row)) {
			return true;
		}
		rangeMin = row;
		rangeMax = row;
		if (inserting) {
			return true;
		}
		int[] rows = table.getSelectedRows();
		int index = -1;
		for (int i = 0; i < rows.length; i++) {
			if (row == rows[i]) {
				index = i;
			}
		}
		if (index != -1) {
			for (int i = index - 1; i >= 0; i--) {
				if (rows[i] + 1 != rows[i + 1]) {
					rangeMin = rows[i + 1];
					break;
				}
				rangeMin = rows[i];
			}
			for (int i = index + 1; i < rows.length; i++) {
				if (rows[i - 1] != rows[i] - 1) {
					rangeMax = rows[i - 1];
					break;
				}
				rangeMax = rows[i];
			}
		}
		return true;
	}
}
