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

import java.awt.BorderLayout;
import java.awt.Point;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JPanel;
import javax.swing.JScrollPane;

import docking.widgets.table.threaded.GThreadedTablePanel;
import docking.widgets.table.threaded.ThreadedTableModel;

public class GFilterTable<ROW_OBJECT> extends JPanel {

	private RowObjectTableModel<ROW_OBJECT> model;
	private GTable table;
	private GTableFilterPanel<ROW_OBJECT> filterPanel;

	private List<ObjectSelectedListener<ROW_OBJECT>> listeners = new ArrayList<>();

	public GFilterTable(RowObjectTableModel<ROW_OBJECT> model) {
		super(new BorderLayout());
		this.model = model;
		buildTable();
	}

	public void dispose() {
		filterPanel.dispose();
	}

	private void buildTable() {
		if (model instanceof ThreadedTableModel) {
			buildThreadedTable();
		}
		else {
			buildNonThreadedTable();
		}
	}

	private void buildNonThreadedTable() {
		table = createTable(model);
		JScrollPane scrollPane = new JScrollPane(table);
		add(scrollPane, BorderLayout.CENTER);
		filterPanel = createTableFilterPanel(table, model);
		add(filterPanel, BorderLayout.SOUTH);
	}

	protected GTable createTable(RowObjectTableModel<ROW_OBJECT> tableModel) {
		GTable gTable = new GTable(tableModel);
		addTableSelectionListener(gTable);
		return gTable;
	}

	private void addTableSelectionListener(GTable gTable) {
		gTable.getSelectionModel().addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				rowSelectionChanged();
			}
		});
	}

	private void buildThreadedTable() {
		@SuppressWarnings("unchecked")
		GThreadedTablePanel<ROW_OBJECT> tablePanel =
			createThreadedTablePanel((ThreadedTableModel<ROW_OBJECT, ?>) model);
		table = tablePanel.getTable();
		addTableSelectionListener(table);

		add(tablePanel, BorderLayout.CENTER);
		filterPanel = createTableFilterPanel(table, model);
		add(filterPanel, BorderLayout.SOUTH);
	}

	protected GTableFilterPanel<ROW_OBJECT> createTableFilterPanel(GTable gTable,
			RowObjectTableModel<ROW_OBJECT> tableModel) {
		return new GTableFilterPanel<>(gTable, tableModel);
	}

	protected GThreadedTablePanel<ROW_OBJECT> createThreadedTablePanel(
			ThreadedTableModel<ROW_OBJECT, ?> threadedModel) {

		return new GThreadedTablePanel<>(threadedModel);
	}

	public GTable getTable() {
		return table;
	}

	public GTableFilterPanel<ROW_OBJECT> getFilterPanel() {
		return filterPanel;
	}

	public RowObjectTableModel<ROW_OBJECT> getModel() {
		return model;
	}

	public boolean isInView(ROW_OBJECT o) {
		return filterPanel.isInView(o);
	}

	public void clearSelection() {
		table.clearSelection();
		table.getSelectionManager().clearSavedSelection();
	}

	/**
	 * Returns all row objects corresponding to all selected rows in the table.
	 * @return all row objects corresponding to all selected rows in the table.
	 */
	public List<ROW_OBJECT> getSelectedRowObjects() {
		List<ROW_OBJECT> items = filterPanel.getSelectedItems();
		return items;
	}

	public ROW_OBJECT getSelectedRowObject() {
		ROW_OBJECT item = filterPanel.getSelectedItem();
		return item;
	}

	public void setSelectedRowObject(ROW_OBJECT rowObject) {
		filterPanel.setSelectedItem(rowObject);
	}

	public ROW_OBJECT getRowObject(int viewRow) {
		ROW_OBJECT rowObject = filterPanel.getRowObject(viewRow);
		return rowObject;
	}

	public ROW_OBJECT getItemAt(Point point) {
		int viewRow = table.rowAtPoint(point);
		if (viewRow < 0) {
			return null;
		}

		ROW_OBJECT rowObject = filterPanel.getRowObject(viewRow);
		return rowObject;
	}

	public void setTableFilter(TableFilter<ROW_OBJECT> tableFilter) {
		filterPanel.setSecondaryFilter(tableFilter);
	}

	public void addSelectionListener(ObjectSelectedListener<ROW_OBJECT> l) {
		listeners.add(l);
	}

	public void removeSelectionListener(ObjectSelectedListener<ROW_OBJECT> l) {
		listeners.remove(l);
	}

	private void rowSelectionChanged() {
		ROW_OBJECT selectedObject = null;
		if (table.getSelectedRow() >= 0) {
			selectedObject = getSelectedRowObject();
		}

		if (selectedObject == null) {
			rowSelectionCleared();
			return; // can happen for transient events
		}

		rowSelected(selectedObject);
	}

	protected void rowSelectionCleared() {
		for (ObjectSelectedListener<ROW_OBJECT> l : listeners) {
			l.objectSelected(null);
		}
	}

	/**
	 * Notifies listeners that an item was selected
	 * @param selectedObject the selected row object
	 */
	protected void rowSelected(ROW_OBJECT selectedObject) {
		for (ObjectSelectedListener<ROW_OBJECT> l : listeners) {
			l.objectSelected(selectedObject);
		}
	}

	public void focusFilter() {
		filterPanel.requestFocus();
	}

	public void setFiterText(String text) {
		filterPanel.setFilterText(text);
	}
}
