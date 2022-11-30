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
package docking.widgets.table;

import java.awt.*;
import java.awt.font.TextAttribute;
import java.text.AttributedString;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.*;

import generic.theme.*;
import resources.*;
import resources.icons.EmptyIcon;
import resources.icons.TranslateIcon;

public class GTableHeaderRenderer extends DefaultTableCellRenderer {

	private static final Color SORT_NUMBER_FG_COLOR = new GColor("color.fg");

	private static final int PADDING_FOR_COLUMN_NUMBER = 10;
	private static final Icon UP_ICON =
		ResourceManager.getScaledIcon(Icons.SORT_ASCENDING_ICON, 14, 14);
	private static final Icon DOWN_ICON =
		ResourceManager.getScaledIcon(Icons.SORT_DESCENDING_ICON, 14, 14);
	private static final int DEFAULT_MIN_HEIGHT = UP_ICON.getIconHeight();

	private static final Icon EMPTY_ICON = new EmptyIcon(0, 0);
	private static final Icon FILTER_ICON =
		ResourceManager.getScaledIcon(new GIcon("icon.widget.filterpanel.filter.off"), 12, 12);

	private static final Icon PENDING_ICON = new GIcon("icon.widget.table.header.pending");

	private Icon primaryIcon = EMPTY_ICON;
	private Icon helpIcon = EMPTY_ICON;
	protected boolean isPaintingPrimarySortColumn;

	private TableCellRenderer delegate;

	@Override
	public Component getTableCellRendererComponent(JTable table, Object value,
			boolean isSelected, boolean hasFocus, int row, int column) {

		JTableHeader header = table.getTableHeader();
		delegate = header.getDefaultRenderer();

		Component rendererComponent =
			delegate.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

		int modelIndex = table.convertColumnIndexToModel(column);
		TableModel model = table.getModel();
		VariableColumnTableModel variableModel = VariableColumnTableModel.from(model);
		if (variableModel != null) {
			String text = variableModel.getColumnDisplayName(modelIndex);
			if (rendererComponent instanceof JLabel) {
				((JLabel) rendererComponent).setText(text);
			}
		}

		primaryIcon = getIcon(model, modelIndex);
		helpIcon = getHelpIcon(table, column);

		return this;
	}

	@Override
	public void setBounds(int x, int y, int w, int h) {
		super.setBounds(x, y, w, h);
		((Component) delegate).setBounds(x, y, w, h);
	}

	@Override
	public void paint(Graphics g) {

		JLabel label = (JLabel) delegate;
		String text = label.getText();
		String clippedText = checkForClipping(label, text);
		if (!text.equals(clippedText)) {
			label.setText(clippedText);
		}

		label.paint(g);

		// paint our items after the delegate call so that we paint on top
		super.paint(g);
	}

	private String checkForClipping(JLabel label, String text) {

		Point helpPoint = getHelpIconLocation();
		int padding = 10;
		int iconStartX = helpPoint.x - primaryIcon.getIconWidth() - padding;

		FontMetrics metrics = label.getFontMetrics(label.getFont());
		int horizontalAlignment = label.getHorizontalAlignment();
		Rectangle bounds = label.getBounds();
		int availableWidth = iconStartX + primaryIcon.getIconWidth();
		if (horizontalAlignment == CENTER) {
			availableWidth = iconStartX - padding;
		}

		String clippedText = SwingUtilities.layoutCompoundLabel(
			label,
			metrics,
			text,
			primaryIcon,
			label.getVerticalAlignment(),
			label.getHorizontalAlignment(),
			label.getVerticalTextPosition(),
			label.getHorizontalTextPosition(),
			new Rectangle(0, 0, availableWidth, bounds.height),
			new Rectangle(iconStartX, 0, primaryIcon.getIconWidth(), bounds.height),
			new Rectangle(0, 0, iconStartX, bounds.height),
			label.getIconTextGap());
		return clippedText;
	}

	@Override
	protected void paintChildren(Graphics g) {

		// The help icon paints at the end of the cell; place the main icon to the left of that
		Point helpPoint = getHelpIconLocation();
		int offset = 4;
		int x = helpPoint.x - primaryIcon.getIconWidth() - offset;
		int y = getIconStartY(primaryIcon.getIconHeight());
		primaryIcon.paintIcon(this, g, x, y);

		helpIcon.paintIcon(this, g, helpPoint.x, helpPoint.y);
	}

	private Point getHelpIconLocation() {

		int right = getWidth();
		int offset = 2;
		int helpIconWidth = GTableHeader.HELP_ICON_HEIGHT;

		// we want the icon on the right-hand size of the header, at the top
		int x = right - helpIconWidth - offset;
		int y = offset; // down a bit
		return new Point(x, y);
	}

	@Override
	// overridden to enforce a minimum height for the icon we use
	public Dimension getPreferredSize() {
		Dimension preferredSize = super.getPreferredSize();
		if (delegate != null) {
			return ((Component) delegate).getPreferredSize();
		}

		Border currentBorder = getBorder();
		int minHeight = DEFAULT_MIN_HEIGHT;
		if (currentBorder != null) {
			Insets borderInsets = currentBorder.getBorderInsets(this);
			minHeight += borderInsets.top + borderInsets.bottom;
		}
		preferredSize.height = Math.max(preferredSize.height, minHeight);
		return preferredSize;
	}

	private Icon getIcon(TableModel model, int columnModelIndex) {
		Icon icon = null;
		if (model instanceof SortedTableModel) {
			icon = getSortIcon(icon, columnModelIndex, model);
		}
		if (isColumnFiltered(model, columnModelIndex)) {
			icon = combineIcons(FILTER_ICON, icon);
		}

		if (icon != null) {
			return icon;
		}
		return EMPTY_ICON;
	}

	private Icon combineIcons(Icon icon1, Icon icon2) {
		if (icon1 == null) {
			return icon2;
		}
		if (icon2 == null) {
			return icon1;
		}

		int padding = 2;
		int w1 = icon1.getIconWidth();
		int w2 = icon2.getIconWidth();
		int h1 = icon1.getIconHeight();
		int fullWidth = w1 + padding + w2;
		MultiIcon icon = new MultiIcon(new EmptyIcon(fullWidth, h1));
		icon.addIcon(icon1);
		int rightShift = w1 + padding;
		icon.addIcon(new TranslateIcon(icon2, rightShift, 0));
		return icon;
	}

	private boolean isColumnFiltered(TableModel model, int columnModelIndex) {
		if (!(model instanceof RowObjectFilterModel<?>)) {
			return false;
		}
		RowObjectFilterModel<?> filterModel = (RowObjectFilterModel<?>) model;
		TableFilter<?> tableFilter = filterModel.getTableFilter();
		if (tableFilter == null) {
			return false;
		}
		return tableFilter.hasColumnFilter(columnModelIndex);
	}

	private Icon getHelpIcon(JTable table, int currentColumnIndex) {

		JTableHeader tableHeader = table.getTableHeader();
		if (!(tableHeader instanceof GTableHeader)) {
			return EMPTY_ICON;
		}

		GTableHeader tooltipTableHeader = (GTableHeader) tableHeader;
		int hoveredColumnIndex = tooltipTableHeader.getHoveredHeaderColumnIndex();
		if (hoveredColumnIndex != currentColumnIndex) {
			return EMPTY_ICON;
		}

		Icon icon = tooltipTableHeader.getHelpIcon();
		if (icon != null) {
			return icon;
		}
		return EMPTY_ICON;
	}

	private Icon getSortIcon(Icon icon, int realIndex, TableModel model) {
		SortedTableModel sortedModel = (SortedTableModel) model;
		TableSortState columnSortStates = sortedModel.getTableSortState();

		boolean sortPending = false;
		if (model instanceof AbstractSortedTableModel) {
			@SuppressWarnings("rawtypes")
			AbstractSortedTableModel abstractSortedModel = (AbstractSortedTableModel) model;
			sortPending = abstractSortedModel.isSortPending();
			if (sortPending) {
				TableSortState pendingTableState = abstractSortedModel.getPendingSortState();
				ColumnSortState pendingColumnState =
					pendingTableState.getColumnSortState(realIndex);
				if (pendingColumnState != null) {
					return getColumnIconForSortState(columnSortStates, pendingColumnState, true);
				}
			}
		}

		ColumnSortState sortState = columnSortStates.getColumnSortState(realIndex);
		if (sortState == null) {
			return null;
		}

		icon = getColumnIconForSortState(columnSortStates, sortState, false);
		if (sortPending) {
			// indicate that the current sort is stale
			icon = ResourceManager.getDisabledIcon(icon, 65);
		}

		return icon;
	}

	private Icon getColumnIconForSortState(TableSortState columnSortStates,
			ColumnSortState sortState, boolean isPendingSort) {

		Icon icon = (sortState.isAscending() ? UP_ICON : DOWN_ICON);
		if (columnSortStates.getSortedColumnCount() != 1) {
			MultiIcon multiIcon = new MultiIcon(icon);
			int sortOrder = sortState.getSortOrder();
			if (sortOrder == 1) {
				isPaintingPrimarySortColumn = true;
			}
			String numberString = Integer.toString(sortOrder);
			multiIcon.addIcon(new NumberPainterIcon(icon.getIconWidth() + PADDING_FOR_COLUMN_NUMBER,
				icon.getIconHeight(), numberString));
			icon = multiIcon;
		}
		else {
			isPaintingPrimarySortColumn = true;
		}

		if (isPendingSort) {
			icon = PENDING_ICON;
		}

		return icon;
	}

	private int getIconStartY(int iconHeight) {

		int height = getHeight();
		int middle = height / 2;
		int halfHeight = iconHeight / 2;
		int y = middle - halfHeight;
		return y;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class NumberPainterIcon implements Icon {

		private static final String FONT_ID = "font.table.header.number";
		private final int iconWidth;
		private int numberWidth;
		private final int iconHeight;
		private final String numberText;

		public NumberPainterIcon(int width, int height, String numberText) {
			this.iconWidth = width;
			this.iconHeight = height;
			this.numberText = numberText;

			Font font = Gui.getFont(FONT_ID);
			FontMetrics fontMetrics = getFontMetrics(font);
			numberWidth = fontMetrics.stringWidth(numberText);
		}

		@Override
		public int getIconHeight() {
			return iconHeight;
		}

		@Override
		public int getIconWidth() {
			return iconWidth + numberWidth;
		}

		@Override
		public void paintIcon(Component c, Graphics g, int x, int y) {

			Font font = Gui.getFont(FONT_ID);
			g.setFont(font);
			FontMetrics fontMetrics = g.getFontMetrics();
			int numberHeight = fontMetrics.getAscent();

			int padding = 2;

			// draw the number on the right...
			int startX = x + (iconWidth - numberWidth) + padding;

			// ...and at the same start y as the sort icon
			int iconY = getIconStartY(iconHeight);
			int textBaseline = iconY + numberHeight - padding;

			AttributedString as = new AttributedString(numberText);
			as.addAttribute(TextAttribute.FOREGROUND, SORT_NUMBER_FG_COLOR);
			as.addAttribute(TextAttribute.WEIGHT, TextAttribute.WEIGHT_BOLD);
			as.addAttribute(TextAttribute.FAMILY, font.getFamily());
			as.addAttribute(TextAttribute.SIZE, font.getSize2D());

			g.drawString(as.getIterator(), startX, textBaseline);

		}

	}
}
