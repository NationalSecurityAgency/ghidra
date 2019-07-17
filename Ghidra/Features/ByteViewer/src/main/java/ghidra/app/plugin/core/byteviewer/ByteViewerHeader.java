/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.byteviewer;

import ghidra.util.table.GhidraTable;

import java.awt.*;
import java.util.HashMap;
import java.util.Iterator;

import javax.swing.*;
import javax.swing.event.TableColumnModelListener;
import javax.swing.table.*;

/**
 * JTableHeader that uses the default table column model to manage 
 * TableColumns. Sizes the column according to its corresponding viewer
 * component. Allows columns to be moved.
 */
class ByteViewerHeader extends JTableHeader implements Scrollable {

	private TableColumnModel columnModel;
	private Component container;

	private int separatorWidth;
	private HashMap<Component, TableColumn> components; // table of components that map to columns

	/**
	 * Constructor 
	 * @param container Container that will be used to calculate the 
	 * preferred size
	 */
	ByteViewerHeader(Component container) {

		super();

		this.container = container;
		components = new HashMap<Component, TableColumn>();
		Font font = new Font("Tahoma", Font.PLAIN, 11);
		setFont(font);
		setResizingAllowed(false);
		table = new GhidraTable();
		setTable(table);
		table.setTableHeader(this);
		columnModel = getColumnModel();
		columnModel.setColumnMargin(0);
		JSeparator s = new JSeparator(SwingConstants.VERTICAL);
		separatorWidth = s.getPreferredSize().width;
	}

	/**
	 * Add a new column.
	 * @param name name that will be displayed in the column
	 * @param c corresponding viewer component 
	 */
	public void addColumn(String name, Component c) {

		TableColumn col = new TableColumn(components.size());

		col.setHeaderValue(name);
//        col.setMinWidth((2*margin) + name.length() * unitWidth);
		col.setIdentifier(c);
		columnModel.addColumn(col);
		components.put(c, col);
		resizeAndRepaint();

	}

	/**
	 * Remove a column.
	 * @param c component that corresponds to a column to be removed.
	 */
	public void removeColumn(Component c) {
		TableColumn col = components.get(c);

		if (col != null) {
			columnModel.removeColumn(col);
			components.remove(c);
			setSize(getPreferredSize());
			resizeAndRepaint();
		}
	}

	/**
	 * Get the preferred size of the table header.
	 */
	@Override
	public Dimension getPreferredSize() {
		Dimension d = super.getPreferredSize();
		d.height += 4;
		return d;
	}

	/**
	 * Set the name on the column.
	 * @param c component that maps to the column
	 * @param name name to set on the column header
	 */
	public void setColumnName(Component c, String name) {
		TableColumn col = components.get(c);

		if (col != null) {
			col.setHeaderValue(name);
			recomputeColumnHeaders();
			resizeAndRepaint();
		}
	}

	/**
	 * Add a column model listener.
	 */
	public void addColumnModelListener(TableColumnModelListener l) {
		columnModel.addColumnModelListener(l);
	}

	/**
	 * Remove a column model listener.
	 */
	public void removeColumnModelListener(TableColumnModelListener l) {
		columnModel.removeColumnModelListener(l);
	}

	@Override
	public void paint(Graphics g) {
		recomputeColumnHeaders();
		super.paint(g);
	}

	// Scrollable interface methods

	@Override
	public Dimension getPreferredScrollableViewportSize() {
		return getPreferredSize();
	}

	@Override
	public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
		return 1;
	}

	@Override
	public boolean getScrollableTracksViewportHeight() {
		return false;
	}

	@Override
	public boolean getScrollableTracksViewportWidth() {
		return false;
	}

	@Override
	public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
		return 1;
	}

	/////////////////////////////////////////////////////////////////
	// *** private methods ***
	/////////////////////////////////////////////////////////////////
	/**
	 * Recompute the width of the column headers based on the width
	 * of the corresponding component.
	 */
	private void recomputeColumnHeaders() {

		Iterator<Component> iter = components.keySet().iterator();

		while (iter.hasNext()) {

			Component c = iter.next();
			TableColumn col = components.get(c);
			int width = c.getPreferredSize().width;
			int index = columnModel.getColumnIndex(col.getIdentifier());

			if (index == 0) {
				width += separatorWidth / 2;
			}
			else if (index == components.size() - 1) {
				width += separatorWidth / 2;
			}
			else {
				width += separatorWidth;
			}
			col.setMinWidth(width);
			col.setMaxWidth(width);
			col.setPreferredWidth(width);
		}

	}

}
