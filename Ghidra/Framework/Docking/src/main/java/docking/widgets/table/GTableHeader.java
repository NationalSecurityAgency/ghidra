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
import java.awt.event.*;

import javax.swing.*;
import javax.swing.table.*;

import docking.DockingWindowManager;
import docking.help.HelpService;
import docking.widgets.table.columnfilter.ColumnBasedTableFilter;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

/**
 * A special header for GhidraTables to handle things like tooltips and hover information.
 */
public class GTableHeader extends JTableHeader {

	private static final Cursor HAND_CURSOR = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR);

	/** This is the cursor used by BasicTableHeaderUI to tell the user they can resize a column  */
	private static final Cursor RESIZE_CURSOR = Cursor.getPredefinedCursor(Cursor.E_RESIZE_CURSOR);

	private static final int HELP_ICON_HEIGHT = 8;
	private static final Icon HELP_ICON = ResourceManager.getScaledIcon(
		ResourceManager.loadImage("images/info_small.png"), HELP_ICON_HEIGHT, HELP_ICON_HEIGHT);
	private static final Icon HELP_HOVERED_ICON =
		ResourceManager.getScaledIcon(ResourceManager.loadImage("images/info_small_hover.png"),
			HELP_ICON_HEIGHT, HELP_ICON_HEIGHT);

	private final GTable gTable;

	private boolean isOverHelpIcon = false;
	private int hoveredColumnIndex = -1;

	GTableHeader(GTable table) {
		super(table.getColumnModel());
		gTable = table;
		ToolTipManager.sharedInstance().registerComponent(this);

		addMouseListener(new MouseAdapter() {
			@Override
			public void mouseEntered(MouseEvent e) {
				// no-op
			}

			@Override
			public void mouseExited(MouseEvent e) {
				if (!isHelpEnabled()) {
					return;
				}

				restoreCursor();
				hoveredColumnIndex = -1;
				repaint();
			}
		});

		addMouseMotionListener(new MouseMotionListener() {
			@Override
			public void mouseDragged(MouseEvent e) {
				// no-op
			}

			@Override
			public void mouseMoved(MouseEvent e) {
				if (!isHelpEnabled()) {
					return;
				}

				restoreCursor();
				int columnIndex = columnAtPoint(e.getPoint());
				if (columnIndex < 0) {
					return;
				}

				hoveredColumnIndex = columnIndex;
				isOverHelpIcon = isMouseOverHelpIcon(e.getPoint(), columnIndex);
				if (isOverHelpIcon) {
					installCursor();
				}

				repaint();
			}
		});

		HelpLocation helpLocation = new HelpLocation("Tables", "GhidraTableHeaders");
		DockingWindowManager.getHelpService().registerHelp(this, helpLocation);
	}

	private boolean isHelpEnabled() {
		return gTable.isColumnHeaderPopupEnabled();
	}

	private void installCursor() {
		if (!isHelpEnabled()) {
			return;
		}

		Cursor currentCursor = getCursor();
		if (currentCursor != RESIZE_CURSOR) {
			setCursor(HAND_CURSOR);
		}
	}

	private void restoreCursor() {
		if (!isHelpEnabled()) {
			return;
		}

		Cursor currentCursor = getCursor();
		if (currentCursor == HAND_CURSOR) {
			setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
		}
	}

	private boolean isMouseOverHelpIcon(Point point, int columnIndex) {
		if (!canFindHelp()) {
			return false;
		}

		Rectangle headerRect = getHeaderRect(columnIndex);
		int padding = 2; // add some padding, since we are dealing with really small sizes
		int borderWidthTop = 2;
		int borderWidthRight = 4;
		int paddedHeight = HELP_ICON_HEIGHT + padding;
		int paddedWidth = paddedHeight;
		int headerEndX = headerRect.x + headerRect.width;
		int helpIconStartX = headerEndX - (paddedWidth + borderWidthRight);
		int hoverWidth = headerEndX - helpIconStartX;
		int hoverHeight = paddedHeight + borderWidthTop;
		Rectangle helpIconRect = new Rectangle(helpIconStartX, 0, hoverWidth, hoverHeight);
		return helpIconRect.contains(point);
	}

	boolean isMouseOverHelpIcon() {
		return isOverHelpIcon;
	}

	int getHoveredHeaderColumnIndex() {
		return hoveredColumnIndex;
	}

	Icon getHelpIcon() {
		if (!canFindHelp()) {
			return null;
		}

		if (!isHelpEnabled()) {
			return null;
		}

		if (isOverHelpIcon) {
			return HELP_HOVERED_ICON;
		}
		return HELP_ICON;
	}

	private boolean canFindHelp() {
		HelpService helpService = DockingWindowManager.getHelpService();
		return helpService.helpExists();
	}

	@Override
	public String getToolTipText(MouseEvent e) {
		int columnIndex = columnAtPoint(e.getPoint());
		if (columnIndex < 0) {
			return null;
		}

		if (isOverHelpIcon) {
			return "Click here for table header help";
		}

		StringBuilder ttBuilder = new StringBuilder();

		TableColumn column = getColumnModel().getColumn(columnIndex);
		TableModel model = gTable.getModel();

		int realIndex = gTable.convertColumnIndexToModel(columnIndex);

		String columnFilterToolTip = getColumnFilterToolTip(model, realIndex);
		VariableColumnTableModel variableModel = VariableColumnTableModel.from(model);
		if (variableModel != null) {
			String description = variableModel.getColumnDescription(realIndex);
			if (description != null) {
				ttBuilder.append(description);
			}
		}

		if (columnFilterToolTip != null) {
			ttBuilder.append("<br><b>Filters: </b");
			ttBuilder.append(columnFilterToolTip);

		}

		if (ttBuilder.length() != 0) {
			return HTMLUtilities.wrapAsHTML(ttBuilder.toString());
		}

		TableCellRenderer headerRenderer = column.getHeaderRenderer();
		Component component = headerRenderer.getTableCellRendererComponent(getTable(),
			column.getHeaderValue(), false, false, 0, 0);
		int prefWidth = component.getPreferredSize().width;
		int cellWidth = getHeaderRect(columnIndex).width;
		if (prefWidth > cellWidth) {
			return column.getHeaderValue().toString();
		}
		if (component instanceof GTableHeaderRenderer) {
			GTableHeaderRenderer gthr = (GTableHeaderRenderer) component;
			if (gthr.isTextOccluded()) {
				return column.getHeaderValue().toString();
			}
		}

		// handle the case where the user has specifically added a tooltip string
		if (component instanceof JComponent) {
			JComponent jComponent = (JComponent) component;
			return jComponent.getToolTipText();
		}

		return null;
	}

	private String getColumnFilterToolTip(TableModel model, int columnIndex) {
		ColumnBasedTableFilter<?> columnTableFilter = getColumnTableFilter(model);
		if (columnTableFilter == null) {
			return null;
		}
		return columnTableFilter.getToolTip(columnIndex);
	}

	private ColumnBasedTableFilter<?> getColumnTableFilter(TableModel model) {
		if (!(model instanceof RowObjectFilterModel<?>)) {
			return null;
		}
		RowObjectFilterModel<?> filterModel = (RowObjectFilterModel<?>) model;
		TableFilter<?> tableFilter = filterModel.getTableFilter();
		if (tableFilter == null) {
			return null;
		}
		if (tableFilter instanceof ColumnBasedTableFilter<?>) {
			return (ColumnBasedTableFilter<?>) tableFilter;
		}
		if (!(tableFilter instanceof CombinedTableFilter<?>)) {
			return null;
		}
		CombinedTableFilter<?> combinedFilter = (CombinedTableFilter<?>) tableFilter;
		for (int i = 0; i < combinedFilter.getFilterCount(); i++) {
			TableFilter<?> filter = combinedFilter.getFilter(i);
			if (filter instanceof ColumnBasedTableFilter<?>) {
				return (ColumnBasedTableFilter<?>) filter;
			}
		}
		return null;

	}

	/**
	 * Overridden to fix a 'bug' in Java whereby it tries to render columns that we have just
	 * removed when editing the visible columns.
	 *
	 * @return the column being dragged by the user
	 * @see JTableHeader#getDraggedColumn()
	 */
	@Override
	public TableColumn getDraggedColumn() {
		if (draggedColumn == null) {
			return null;
		}

		// make sure the column has not been invisible-ized
		for (int column = 0; column < columnModel.getColumnCount(); column++) {
			TableColumn modelsColumn = columnModel.getColumn(column);
			if (modelsColumn == draggedColumn) {
				return draggedColumn;
			}
		}
		return null;
	}
}
