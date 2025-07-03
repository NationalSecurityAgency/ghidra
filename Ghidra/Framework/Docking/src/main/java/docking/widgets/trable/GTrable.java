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

import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import javax.swing.*;

import docking.DockingUtils;
import ghidra.util.datastruct.Range;

/**
 * Component that combines the display of a tree and a table. Data is presented in columns like a 
 * table, but rows can have child rows like a tree which are displayed indented in the first
 * column.
 * <P>
 * A GTrable uses two different models: a row model and a column model. The row model contains
 * row objects that contains the data to be displayed on a given row. The column model specifies
 * how to display the data in the row object as a series of column values.
 * <P>
 * The row model also provides information about the parent child relationship of rows. If the
 * model reports that a row can be expanded, an expand control is show on that row. If the row
 * is then expanded, the model will then report additional rows immediately below the parent row,
 * pushing any existing rows further down (i.e. all rows below the row being opened have their row
 * indexes increased by the number of rows added.)
 *
 * @param <T> The row object type
 */
public class GTrable<T> extends JComponent
		implements Scrollable, GTrableModeRowlListener {
	private static final int ICON_WIDTH = 16;
	private static final int INDENT_WIDTH = 12;
	private static final int DEFAULT_MAX_VISIBLE_ROWS = 10;
	private static final int DEFAULT_MIN_VISIBLE_ROWS = 10;
	private static OpenCloseIcon OPEN_ICON = new OpenCloseIcon(true, ICON_WIDTH, ICON_WIDTH);
	private static OpenCloseIcon CLOSED_ICON = new OpenCloseIcon(false, ICON_WIDTH, ICON_WIDTH);

	private Color selectionForground = UIManager.getColor("List.selectionForeground");
	private Color selectionBackground = UIManager.getColor("List.selectionBackground");
	private int minVisibleRows = DEFAULT_MIN_VISIBLE_ROWS;
	private int maxVisibleRows = DEFAULT_MAX_VISIBLE_ROWS;

	private int rowHeight = 20;
	private GTrableRowModel<T> rowModel;
	private GTrableColumnModel<T> columnModel;
	private CellRendererPane renderPane;
	private int selectedRow = -1;
	private List<GTrableCellClickedListener> cellClickedListeners = new ArrayList<>();
	private List<Consumer<Integer>> selectedRowConsumers = new ArrayList<>();

	/**
	 * Constructor 
	 * @param rowModel the model that provides the row data.
	 * @param columnModel the model the provides the column information for displaying the data
	 * stored in the row data.
	 */
	public GTrable(GTrableRowModel<T> rowModel, GTrableColumnModel<T> columnModel) {
		this.rowModel = rowModel;
		this.columnModel = columnModel;
		this.rowModel.addListener(this);
		renderPane = new CellRendererPane();
		add(renderPane);
		GTrableMouseListener l = new GTrableMouseListener();
		addMouseListener(l);
		addMouseMotionListener(l);
		addKeyListener(new GTrableKeyListener());
		setFocusable(true);
	}

	/**
	 * Sets a new row model.
	 * @param newRowModel the new row model to use
	 */
	public void setRowModel(GTrableRowModel<T> newRowModel) {
		rowModel.removeListener(this);
		rowModel = newRowModel;
		newRowModel.addListener(this);
	}

	/**
	 * Sets a new column model.
	 * @param columnModel the new column model to use
	 */
	public void setColumnModel(GTrableColumnModel<T> columnModel) {
		this.columnModel = columnModel;
	}

	/**
	 * Sets the preferred number of visible rows to be displayed in the scrollable area.
	 * @param minVisibleRows the minimum number of visible rows.
	 * @param maxVisibleRows the maximum number of visible rows.
	 */
	public void setPreferredVisibleRowCount(int minVisibleRows, int maxVisibleRows) {
		this.minVisibleRows = minVisibleRows;
		this.maxVisibleRows = maxVisibleRows;
	}

	/**
	 * Adds a listener to be notified if the user clicks on a cell in the GTrable.
	 * @param listener the listener to be notified
	 */
	public void addCellClickedListener(GTrableCellClickedListener listener) {
		cellClickedListeners.add(listener);
	}

	/**
	 * Removes a cell clicked listener.
	 * @param listener the listener to be removed
	 */
	public void removeCellClickedListener(GTrableCellClickedListener listener) {
		cellClickedListeners.remove(listener);
	}

	/**
	 * Adds a consumer to be notified when the selected row changes.
	 * @param consumer the consumer to be notified when the selected row changes
	 */
	public void addSelectedRowConsumer(Consumer<Integer> consumer) {
		selectedRowConsumers.add(consumer);
	}

	/**
	 * Removes the consumer to be notified when the selected row changes.
	 * @param consumer the consumer to be removed
	 */
	public void removeSelectedRowConsumer(Consumer<Integer> consumer) {
		selectedRowConsumers.remove(consumer);
	}

	@Override
	public Dimension getPreferredSize() {
		return new Dimension(columnModel.getPreferredWidth(), rowModel.getRowCount() * rowHeight);
	}

	@Override
	public void paint(Graphics g) {
		Rectangle clipBounds = g.getClipBounds();
		int startIndex = getStartIndex(clipBounds);
		int endIndex = getEndIndex(clipBounds);
		for (int index = startIndex; index <= endIndex; index++) {
			drawRow(g, index);
		}
	}

	/**
	 * {@return the range of visible row indices.}
	 */
	public Range getVisibleRows() {
		Container parent = getParent();
		Rectangle rect;
		if (parent instanceof JViewport viewport) {
			rect = viewport.getViewRect();
		}
		else {
			rect = getVisibleRect();
		}
		return new Range(getStartIndex(rect), getEndIndex(rect));
	}

	/**
	 * {@return the currently selected row or -1 if not row is selected.}
	 */
	public int getSelectedRow() {
		return selectedRow;
	}

	/**
	 * Sets the selected row to the given row index
	 * @param rowIndex the row index to select
	 */
	public void setSelectedRow(int rowIndex) {
		if (rowIndex >= 0 && rowIndex < rowModel.getRowCount()) {
			this.selectedRow = rowIndex;
			repaint();
			notifySelectedRowConsumers();
		}
	}

	/**
	 * Deselects any selected row
	 */
	public void clearSelectedRow() {
		this.selectedRow = -1;
		repaint();
	}

	/**
	 * {@return the selection foreground color}
	 */
	public Color getSelectionForeground() {
		return selectionForground;
	}

	/**
	 * {@return the selection background color}
	 */
	public Color getSelectionBackground() {
		return selectionBackground;
	}

	/**
	 * {@return the height of a row in the trable.}
	 */
	public int getRowHeight() {
		return rowHeight;
	}

	/**
	 * {@return the amount the view is scrolled such that the first line is not fully visible.}
	 */
	public int getRowOffcut() {
		Rectangle visibleRect = getVisibleRect();
		int y = visibleRect.y;
		return y % rowHeight;

	}

	@Override
	public Dimension getPreferredScrollableViewportSize() {
		int size = Math.min(rowModel.getRowCount(), maxVisibleRows);
		size = Math.max(size, minVisibleRows);
		return new Dimension(columnModel.getPreferredWidth(), size * rowHeight);
	}

	@Override
	public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation,
			int direction) {
		return 5;
	}

	@Override
	public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation,
			int direction) {
		return 50;
	}

	@Override
	public boolean getScrollableTracksViewportWidth() {
		return true;
	}

	@Override
	public boolean getScrollableTracksViewportHeight() {
		return false;
	}

	/**
	 * Expands the row at the given index.
	 * @param rowIndex the index of the row to expand
	 */
	public void expandRow(int rowIndex) {
		int numRowsAdded = rowModel.expandRow(rowIndex);
		if (selectedRow > rowIndex) {
			setSelectedRow(selectedRow + numRowsAdded);
		}
	}

	/**
	 * Collapse the row (remove any of its descendants) at the given row index.
	 * @param rowIndex the index of the row to collapse
	 */
	public void collapseRow(int rowIndex) {
		int numRowsDeleted = rowModel.collapseRow(rowIndex);
		if (selectedRow > rowIndex) {
			int newSelectedRow = selectedRow - numRowsDeleted;
			if (newSelectedRow < rowIndex) {
				newSelectedRow = rowIndex;
			}
			setSelectedRow(newSelectedRow);
		}
	}

	/**
	 * Fully expands the given row and all its descendants.
	 * @param rowIndex the index of the row to fully expand
	 */
	public void expandRowRecursively(int rowIndex) {
		int startIndentLevel = rowModel.getIndentLevel(rowIndex);
		int numRowsAdded = rowModel.expandRow(rowIndex);
		if (selectedRow > rowIndex) {
			setSelectedRow(selectedRow + numRowsAdded);
		}
		int nextRow = rowIndex + 1;
		while (nextRow < rowModel.getRowCount() &&
			rowModel.getIndentLevel(nextRow) > startIndentLevel) {
			numRowsAdded = rowModel.expandRow(nextRow);
			if (selectedRow > nextRow) {
				setSelectedRow(selectedRow + numRowsAdded);
			}
			nextRow++;
		}
	}

	/**
	 * Expands all rows fully.
	 */
	public void expandAll() {
		int rowIndex = 0;
		for (rowIndex = 0; rowIndex < rowModel.getRowCount(); rowIndex++) {
			int indentLevel = rowModel.getIndentLevel(rowIndex);
			if (indentLevel == 0) {
				expandRowRecursively(rowIndex);
			}
		}
	}

	/**
	 * Collapses all rows.
	 */
	public void collapseAll() {
		int rowIndex = 0;
		for (rowIndex = 0; rowIndex < rowModel.getRowCount(); rowIndex++) {
			int indentLevel = rowModel.getIndentLevel(rowIndex);
			if (indentLevel == 0) {
				collapseRow(rowIndex);
			}
		}

	}

	/**
	 * Scrolls the view to make the currently selected row visible.
	 */
	public void scrollToSelectedRow() {
		if (selectedRow < 0) {
			return;
		}
		Container parent = getParent();
		if (!(parent instanceof JViewport viewport)) {
			return;
		}
		Rectangle viewRect = viewport.getViewRect();
		int yStart = selectedRow * rowHeight;
		int yEnd = yStart + rowHeight;
		if (yStart < viewRect.y) {
			viewport.setViewPosition(new Point(0, yStart));
		}
		else if (yEnd > viewRect.y + viewRect.height) {
			viewport.setViewPosition(new Point(0, yEnd - viewRect.height));
		}
	}

	@Override
	public void trableChanged() {
		setSize(getWidth(), rowModel.getRowCount() * rowHeight);
		revalidate();
		repaint();
	}

	@Override
	public void setBounds(int x, int y, int width, int height) {
		super.setBounds(x, y, width, height);
		columnModel.setWidth(width);
	}

	private void notifySelectedRowConsumers() {
		for (Consumer<Integer> consumer : selectedRowConsumers) {
			consumer.accept(selectedRow);
		}
	}

	private void notifyCellClicked(int row, int column, MouseEvent e) {
		for (GTrableCellClickedListener listener : cellClickedListeners) {
			listener.cellClicked(row, column, e);
		}
	}

	private void drawRow(Graphics g, int rowIndex) {
		T row = rowModel.getRow(rowIndex);
		int width = getWidth();
		boolean isSelected = rowIndex == selectedRow;

		int y = rowIndex * rowHeight;

		Color fg = isSelected ? selectionForground : getForeground();
		Color bg = isSelected ? selectionBackground : getBackground();
		g.setColor(bg);
		g.fillRect(0, y, width, rowHeight);
		GTrableColumn<T, ?> firstColumn = columnModel.getColumn(0);
		int colWidth = firstColumn.getWidth();

		int marginWidth = paintLeftMargin(g, rowIndex, y, colWidth, fg);
		int x = marginWidth;
		paintColumn(g, x, y, colWidth - marginWidth, firstColumn, row, isSelected);

		x = colWidth;
		for (int i = 1; i < columnModel.getColumnCount(); i++) {
			GTrableColumn<T, ?> column = columnModel.getColumn(i);
			colWidth = column.getWidth();
			paintColumn(g, x, y, colWidth, column, row, isSelected);
			x += colWidth;
		}
	}

	private <C> void paintColumn(Graphics g, int x, int y, int width, GTrableColumn<T, C> column,
			T row, boolean isSelected) {

		GTrableCellRenderer<C> renderer = column.getRenderer();
		C columnValue = column.getValue(row);
		Component component = renderer.getCellRenderer(this, columnValue, isSelected, false, 0, 0);

		renderPane.paintComponent(g, component, this, x, y, width, rowHeight);
	}

	private int paintLeftMargin(Graphics g, int rowIndex, int y, int width, Color fg) {
		int x = rowModel.getIndentLevel(rowIndex) * INDENT_WIDTH;
		drawOpenCloseControl(g, rowIndex, x, y, fg);
		return x + ICON_WIDTH;
	}

	private void drawOpenCloseControl(Graphics g, int rowIndex, int x, int y, Color fg) {
		if (!rowModel.isExpandable(rowIndex)) {
			return;
		}
		OpenCloseIcon icon = rowModel.isExpanded(rowIndex) ? OPEN_ICON : CLOSED_ICON;
		icon.setColor(fg);
		icon.paintIcon(this, g, x, y + rowHeight / 2 - icon.getIconHeight() / 2);
	}

	private int getStartIndex(Rectangle clipBounds) {
		if (clipBounds.height == 0) {
			return 0;
		}
		int index = clipBounds.y / rowHeight;
		return Math.min(index, rowModel.getRowCount() - 1);
	}

	private int getEndIndex(Rectangle clipBounds) {
		if (clipBounds.height == 0) {
			return 0;
		}
		int y = clipBounds.y + clipBounds.height - 1;
		return Math.min(y / rowHeight, rowModel.getRowCount() - 1);
	}

	private void toggleOpen(int rowIndex) {
		if (rowIndex < 0) {
			return;
		}
		if (!rowModel.isExpandable(rowIndex)) {
			return;
		}
		if (rowModel.isExpanded(rowIndex)) {
			collapseRow(rowIndex);
		}
		else {
			expandRow(rowIndex);
		}
	}

	private class GTrableMouseListener extends MouseAdapter {
		private static final int TRIGGER_MARGIN = 10;
		private int startDragX = -1;
		private int originalColumnStart;
		private int boundaryIndex;

		@Override
		public void mouseClicked(MouseEvent e) {
			if (e.getButton() != 1) {
				return;
			}

			Point point = e.getPoint();
			int rowIndex = point.y / rowHeight;
			if (isOnOpenClose(rowIndex, point.x)) {
				toggleOpen(rowIndex);
			}
			else {

				int columnIndex = getColumnIndex(rowIndex, point.x);
				if (columnIndex >= 0) {
					notifyCellClicked(rowIndex, columnIndex, e);
				}
			}
		}

		private int getColumnIndex(int rowIndex, int x) {
			int columnIndex = columnModel.getIndex(x);
			if (columnIndex == 0) {
				int indent = rowModel.getIndentLevel(rowIndex) * INDENT_WIDTH;
				if (x < indent) {
					return -1;
				}
			}
			return columnIndex;
		}

		private boolean isOnOpenClose(int rowIndex, int x) {
			if (!rowModel.isExpandable(rowIndex)) {
				return false;
			}
			int indent = rowModel.getIndentLevel(rowIndex) * INDENT_WIDTH;
			return x >= indent && x < indent + ICON_WIDTH;
		}

		@Override
		public void mousePressed(MouseEvent e) {
			Point p = e.getPoint();
			int rowIndex = p.y / rowHeight;

			if (e.getButton() == 1 && isOnOpenClose(rowIndex, p.x)) {
				return;
			}

			int index = findClosestColumnBoundary(e.getPoint().x);

			if (index >= 0) {
				boundaryIndex = index;
				startDragX = e.getPoint().x;
				originalColumnStart = columnModel.getColumn(index).getStartX();
				return;
			}

			if (DockingUtils.isControlModifier(e) && rowIndex == selectedRow) {
				clearSelectedRow();
			}
			else {
				setSelectedRow(rowIndex);
			}
		}

		public int findClosestColumnBoundary(int x) {
			for (int i = 1; i < columnModel.getColumnCount(); i++) {
				GTrableColumn<T, ?> column = columnModel.getColumn(i);
				int columnStart = column.getStartX();
				if (x > columnStart - TRIGGER_MARGIN && x < columnStart + TRIGGER_MARGIN) {
					return i;
				}
			}
			return -1;
		}

		@Override
		public void mouseMoved(MouseEvent e) {
			int index = findClosestColumnBoundary(e.getPoint().x);
			if (index >= 0) {
				setCursor(Cursor.getPredefinedCursor(Cursor.E_RESIZE_CURSOR));
			}
			else {
				setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
			}
		}

		@Override
		public void mouseReleased(MouseEvent e) {
			startDragX = -1;
			boundaryIndex = -1;
		}

		@Override
		public void mouseDragged(MouseEvent e) {
			if (startDragX < 0) {
				return;
			}
			int x = e.getPoint().x;
			int diff = x - startDragX;
			int newColumnStart = originalColumnStart + diff;
			columnModel.moveColumnStart(boundaryIndex, newColumnStart);
			repaint();
		}

	}

	private class GTrableKeyListener extends KeyAdapter {
		@Override
		public void keyPressed(KeyEvent e) {
			switch (e.getKeyCode()) {
				case KeyEvent.VK_DOWN:
					if (selectedRow < rowModel.getRowCount() - 1) {
						setSelectedRow(selectedRow + 1);
						scrollToSelectedRow();
						e.consume();
					}
					break;
				case KeyEvent.VK_UP:
					if (selectedRow > 0) {
						setSelectedRow(selectedRow - 1);
						scrollToSelectedRow();
						e.consume();
					}
					break;
				case KeyEvent.VK_ENTER:
					toggleOpen(selectedRow);
					e.consume();
					break;
			}
		}

		@Override
		public void keyReleased(KeyEvent e) {
			switch (e.getKeyCode()) {
				case KeyEvent.VK_DOWN:
					if (selectedRow < rowModel.getRowCount() - 1) {
						e.consume();
					}
					break;
				case KeyEvent.VK_UP:
					if (selectedRow > 0) {
						e.consume();
					}
					break;
				case KeyEvent.VK_ENTER:
					e.consume();
					break;
			}
		}

		@Override
		public void keyTyped(KeyEvent e) {
			switch (e.getKeyCode()) {
				case KeyEvent.VK_DOWN:
					if (selectedRow < rowModel.getRowCount() - 1) {
						e.consume();
					}
					break;
				case KeyEvent.VK_UP:
					if (selectedRow > 0) {
						e.consume();
					}
					break;
				case KeyEvent.VK_ENTER:
					e.consume();
					break;
			}
		}

	}

}
