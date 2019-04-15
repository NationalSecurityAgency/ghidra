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
import java.awt.geom.Rectangle2D;
import java.text.AttributedString;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;

import docking.widgets.label.GDLabel;
import resources.*;
import resources.icons.EmptyIcon;
import resources.icons.TranslateIcon;

/**
 * The header renderer for GhidraTable.
 * If the table model implements <code>SortedTableModel</code>, then
 * an icon will be displayed in the header of the currently sorted
 * column representing ascending and descending order.
 */
public class GTableHeaderRenderer extends JPanel implements TableCellRenderer {
	private static final int PADDING_FOR_COLUMN_NUMBER = 10;

	private static final Color PRIMARY_SORT_GRADIENT_START = new Color(205, 227, 244);
	private static final Color PRIMARY_SORT_GRADIENT_END = new Color(126, 186, 233);
	private static final Color DEFAULT_GRADIENT_START = Color.WHITE;
	private static final Color DEFAULT_GRADIENT_END = new Color(215, 215, 215);

	private static final Icon UP_ICON =
		ResourceManager.getScaledIcon(Icons.SORT_ASCENDING_ICON, 14, 14);
	private static final Icon DOWN_ICON =
		ResourceManager.getScaledIcon(Icons.SORT_DESCENDING_ICON, 14, 14);
	private static final int DEFAULT_MIN_HEIGHT = UP_ICON.getIconHeight();

	private static final Icon FILTER_ICON =
		ResourceManager.getScaledIcon(ResourceManager.loadImage("images/filter_off.png"), 12, 12);

	private JLabel textLabel = new GDLabel();
	private JLabel iconLabel = new GDLabel();
	private Icon helpIcon = null;
	private CustomPaddingBorder customBorder;
	protected boolean isPaintingPrimarySortColumn;

	public GTableHeaderRenderer() {
		super();

		textLabel.setHorizontalTextPosition(SwingConstants.LEFT);
		iconLabel.setHorizontalAlignment(SwingConstants.RIGHT);

		textLabel.setBorder(createOSSpecificBorder());

		setLayout(new BorderLayout());
		add(textLabel, BorderLayout.CENTER);
		add(iconLabel, BorderLayout.EAST);

		// controls spacing on multiple platforms
		customBorder = new CustomPaddingBorder();
		setBorder(customBorder);
	}

	@Override
	// overridden to paint our help icon over the other components
	protected void paintChildren(Graphics g) {
		super.paintChildren(g);
		paintHelpIcon(g);
	}

	private void paintHelpIcon(Graphics g) {
		if (helpIcon == null) {
			return;
		}

		Point paintPoint = getHelpIconLocation();
		helpIcon.paintIcon(this, g, paintPoint.x, paintPoint.y);
	}

	private Point getHelpIconLocation() {
		// we want the icon on the right-hand size of the header, at the top
		int primaryWidth = iconLabel.getWidth();
		int overlayWidth = helpIcon.getIconWidth();

		// this point is relative to the iconLabel...
		Point paintPoint = new Point(primaryWidth - overlayWidth, 0);

		// ...make the point relative to the parent (this renderer)
		return SwingUtilities.convertPoint(iconLabel, paintPoint, this);
	}

	@Override
	// overridden to enforce a minimum height for the icon we use
	public Dimension getPreferredSize() {
		Dimension preferredSize = super.getPreferredSize();
		Border currentBorder = getBorder();
		int minHeight = DEFAULT_MIN_HEIGHT;
		if (currentBorder != null) {
			Insets borderInsets = currentBorder.getBorderInsets(this);
			minHeight += borderInsets.top + borderInsets.bottom;
		}
		preferredSize.height = Math.max(preferredSize.height, minHeight);
		return preferredSize;
	}

	@Override
	public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
			boolean hasFocus, int row, int column) {

		isPaintingPrimarySortColumn = false; // reset
		Icon icon = null;
		String text = (value == null) ? "" : value.toString();

		JTableHeader header = table.getTableHeader();
		setForeground(header.getForeground());
		setFont(header.getFont());

		// remap the column index to the models column index
		int modelIndex = table.convertColumnIndexToModel(column);
		TableModel model = table.getModel();

		icon = getIcon(model, modelIndex);

		VariableColumnTableModel variableModel = VariableColumnTableModel.from(model);
		if (variableModel != null) {
			text = variableModel.getColumnDisplayName(modelIndex);
		}
		updateHelpIcon(table, column, icon);
		iconLabel.setIcon(icon);
		textLabel.setText(text);

		setOuterBorder(customBorder, column);

		setOpaque(false);
		return this;
	}

	private Icon getIcon(TableModel model, int columnModelIndex) {
		Icon icon = null;
		if (model instanceof SortedTableModel) {
			icon = getSortIcon(icon, columnModelIndex, model);
		}
		if (isColumnFiltered(model, columnModelIndex)) {
			icon = combineIcons(icon, FILTER_ICON);
		}
		return icon;
	}

	private Icon combineIcons(Icon icon1, Icon icon2) {
		if (icon1 == null) {
			return icon2;
		}
		if (icon2 == null) {
			return icon1;
		}
		MultiIcon icon = new MultiIcon(new EmptyIcon(28, 14));
		icon.addIcon(icon2);
		icon.addIcon(new TranslateIcon(icon1, 14, 0));
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

	private void setOuterBorder(CustomPaddingBorder border, int column) {
		if (paintAquaHeaders()) {
			if (column == 0) {
				customBorder.setOuterBorder(new NoSidesLineBorder(Color.GRAY));
				return;
			}
			customBorder.setOuterBorder(new NoRightSideLineBorder(Color.GRAY));
		}
		else {
			customBorder.setOuterBorder(UIManager.getBorder("TableHeader.cellBorder"));
		}
	}

	private boolean paintAquaHeaders() {
		return true;
		// For now we always use the custom --it actually makes the various LaFs look nicer
		// return DockingWindowsLookAndFeelUtils.isUsingAquaUI(getUI());
	}

	@Override
	protected void paintComponent(Graphics g) {
		Graphics2D g2d = (Graphics2D) g;

		Paint backgroundColor = getBackgroundPaint();
		Paint oldPaint = g2d.getPaint();

		g2d.setPaint(backgroundColor);
		g2d.fillRect(0, 0, getWidth(), getHeight());

		g2d.setPaint(oldPaint);
		super.paintComponent(g);
	}

	protected Paint getBackgroundPaint() {
		if (isPaintingPrimarySortColumn) {
			return new GradientPaint(0, 0, PRIMARY_SORT_GRADIENT_START, 0, getHeight() - 11,
				PRIMARY_SORT_GRADIENT_END, true);
		}
		return new GradientPaint(0, 0, DEFAULT_GRADIENT_START, 0, getHeight() - 11,
			DEFAULT_GRADIENT_END, true);
	}

	private void updateHelpIcon(JTable table, int currentColumnIndex, Icon icon) {
		JTableHeader tableHeader = table.getTableHeader();
		if (!(tableHeader instanceof GTableHeader)) {
			helpIcon = null;
			return;
		}

		GTableHeader tooltipTableHeader = (GTableHeader) tableHeader;
		int hoveredColumnIndex = tooltipTableHeader.getHoveredHeaderColumnIndex();
		if (hoveredColumnIndex != currentColumnIndex) {
			helpIcon = null;
			return;
		}

		helpIcon = tooltipTableHeader.getHelpIcon();
	}

	// checked before this method is called
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
			icon = ResourceManager.loadImage("images/hourglass.png");
		}

		return icon;
	}

	/**
	 * Returns true if sorted in ascending order, false if descending.
	 * @return true if sorted in ascending order, false if descending
	 */
	public boolean isSortedAscending() {
		return iconLabel.getIcon() == UP_ICON;
	}

	boolean isTextOccluded() {
		return textLabel.getPreferredSize().getWidth() > textLabel.getWidth();
	}

	private Border createOSSpecificBorder() {
		if (paintAquaHeaders()) {
			return new EmptyBorder(1, 2, 1, 2);
		}
		return new EmptyBorder(0, 2, 0, 2);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class CustomPaddingBorder extends CompoundBorder {
		private CustomPaddingBorder() {
			insideBorder = createOSSpecificBorder();
		}

		void setOuterBorder(Border border) {
			outsideBorder = border;
		}
	}

	private class NoRightSideLineBorder extends LineBorder {
		NoRightSideLineBorder(Color color) {
			super(color);
		}

		@Override
		public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
			// take advantage of our clipping by telling our parent to paint at a point that will
			// be clipped
			super.paintBorder(c, g, x, y, width + 1, height);
		}
	}

	private class NoSidesLineBorder extends LineBorder {
		NoSidesLineBorder(Color color) {
			super(color);
		}

		@Override
		public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
			// take advantage of our clipping by telling our parent to paint at a point that will
			// be clipped
			super.paintBorder(c, g, x - 1, y, width + 5, height);
		}
	}

	private class NumberPainterIcon implements Icon {

		private final int iconWidth;
		private final int iconHeight;
		private final String numberText;

		public NumberPainterIcon(int width, int height, String numberText) {
			iconWidth = width;
			iconHeight = height;
			this.numberText = numberText;
		}

		@Override
		public int getIconHeight() {
			return iconHeight;
		}

		@Override
		public int getIconWidth() {
			return iconWidth;
		}

		@Override
		public void paintIcon(Component c, Graphics g, int x, int y) {
			int fontSize = 12;
			String fontFamily = "arial";
			Font font = new Font(fontFamily, Font.BOLD, fontSize);
			g.setFont(font);
			FontMetrics fontMetrics = g.getFontMetrics();
			Rectangle2D stringBounds = fontMetrics.getStringBounds(numberText, g);
			int numberWidth = (int) stringBounds.getWidth();
			int numberHeight = fontMetrics.getAscent();

			int insetPadding = 2;

			// draw the number on the right...
			int startX = x + (iconWidth - numberWidth) - insetPadding;

			// ...and in the upper portion
			int textBaseline = numberHeight;

			AttributedString as = new AttributedString(numberText);
			as.addAttribute(TextAttribute.FOREGROUND, Color.BLACK);
			as.addAttribute(TextAttribute.WEIGHT, TextAttribute.WEIGHT_BOLD);
			as.addAttribute(TextAttribute.FAMILY, fontFamily);
			as.addAttribute(TextAttribute.SIZE, (float) fontSize);

			g.drawString(as.getIterator(), startX, textBaseline);
		}

	}
}
