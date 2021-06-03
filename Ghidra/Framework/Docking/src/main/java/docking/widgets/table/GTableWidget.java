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
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.lang.reflect.Method;
import java.util.*;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

/**
 * A GUI that provides a filterable table.  You are required to provide the method names
 * of <code>T</code> that should be used to create columns in the table.
 *
 * @param <T> the row object type that will be in the table
 */
public class GTableWidget<T> extends JPanel {

	private AnyObjectTableModel<T> myModel;
	private GFilterTable<T> gFilterTable;
	private GTable table;
	private TableItemPickedListener<T> listener;

	public GTableWidget(String modelName, Class<T> tClass, String... methodNames) {
		this(modelName, tClass, Arrays.asList(methodNames));
	}

	public GTableWidget(String modelName, Method... methods) {
		this(modelName, Arrays.asList(methods));
	}

	public GTableWidget(String modelName, Class<T> tClass, List<String> methodNames) {
		super(new BorderLayout());
		AnyObjectTableModel<T> model = new AnyObjectTableModel<>(modelName, tClass, methodNames);
		init(model);
	}

	public GTableWidget(String modelName, List<Method> methodNames) {
		super(new BorderLayout());
		AnyObjectTableModel<T> model = new AnyObjectTableModel<>(modelName, methodNames);
		init(model);
	}

	private void init(AnyObjectTableModel<T> model) {
		this.myModel = model;
		this.gFilterTable = new GFilterTable<>(model);
		this.table = gFilterTable.getTable();
		table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
		table.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (!e.isShiftDown()) {
					processMouseClicked(e);
				}
			}
		});

		add(gFilterTable);
	}

	/**
	 * Sets the column preferred widths.  If you give less widths then there are columns, then
	 * the widths will be applied in order, with the remaining columns going untouched.
	 * <p>
	 * Note: this method needs to be called after building your columns. So, call this after
	 * making any calls to {@link #addColumn(AbstractDynamicTableColumn)}.
	 * <p>
	 * <b>WARNING!</b>  If you set the widths to a size that is smaller than the total display,
	 * then the table model will apply the extra space equally across your columns, resulting
	 * in sizes that you did not set.  So, the best way to use this method is to set the
	 * actual preferred size for your small columns and then set a very large size (400 or so)
	 * for your columns that can be any size.
	 * <p>
	 *
	 * @param widths the widths to apply
	 */
	public void setColumnPreferredWidths(int... widths) {
		int columnCount = table.getColumnCount();
		int n = Math.min(widths.length, columnCount);
		TableColumnModel model = table.getColumnModel();
		for (int i = 0; i < n; i++) {
			TableColumn column = model.getColumn(i);
			int width = widths[i];
			if (width == 75) {
				// Horrible Code: we have special knowledge that a value of 75 is the default
				// column size, which we use in TableColumnModelState to signal that we can
				// override the size.  So, if the user sets that value, then change it to
				// override our algorithm.
				width = 76;
			}
			column.setWidth(width);
			column.setPreferredWidth(widths[i]);
		}
	}

	public void setSortColumn(int column) {
		myModel.setTableSortState(TableSortState.createDefaultSortState(column));
	}

	public void setSortColumn(int column, boolean ascending) {
		myModel.setTableSortState(TableSortState.createDefaultSortState(column, ascending));
	}

	protected void processMouseClicked(MouseEvent e) {
		if (listener == null) {
			return;
		}

		if (e.getClickCount() != 2) {
			return;
		}

		int rowAtPoint = table.rowAtPoint(e.getPoint());
		if (rowAtPoint < 0) {
			return;
		}

		listener.itemPicked(gFilterTable.getSelectedRowObject());
	}

	public void setItemPickListener(TableItemPickedListener<T> listener) {
		this.listener = listener;
	}

	public List<T> getData() {
		return myModel.getModelData();
	}

	public void setData(List<T> data) {
		myModel.setModelData(data);
	}

	public void setData(Collection<T> data) {
		List<T> list = null;
		if (data instanceof List) {
			list = (List<T>) data;
		}
		else {
			list = new ArrayList<>(data);
		}
		setData(list);
	}

	public List<T> getSelectedRowObjects() {
		return gFilterTable.getSelectedRowObjects();
	}

	public int getSelectedRowCount() {
		return table.getSelectedRowCount();
	}

	public void addSelectionListener(ObjectSelectedListener<T> l) {
		gFilterTable.addSelectionListener(l);
	}

	public void removeSelectionListener(ObjectSelectedListener<T> l) {
		gFilterTable.removeSelectionListener(l);
	}

	public T getItemAt(Point point) {
		return gFilterTable.getItemAt(point);
	}

	public AnyObjectTableModel<T> getModel() {
		return myModel;
	}

	public void addColumn(AbstractDynamicTableColumn<T, ?, Object> column) {
		myModel.addTableColumn(column);
	}

	public void addColumn(AbstractDynamicTableColumn<T, ?, Object> column, int index) {
		myModel.addTableColumn(column, index, true);
	}

	public int getRowCount() {
		return table.getRowCount();
	}

	public T getRowObject(int row) {
		return gFilterTable.getRowObject(row);
	}

	public void selectRow(int row) {
		table.selectRow(row);
	}

	public void selectRowObject(T rowObject) {
		gFilterTable.setSelectedRowObject(rowObject);
	}

	public int getSelectedRow() {
		return table.getSelectedRow();
	}

	public int rowAtPoint(Point point) {
		return table.rowAtPoint(point);
	}

	public boolean isRowSelected(int row) {
		return table.isRowSelected(row);
	}

	public GTable getTable() {
		return table;
	}

	public void focusFilter() {
		gFilterTable.focusFilter();
	}

	public void setFilterText(String text) {
		gFilterTable.setFiterText(text);
	}

	public void dispose() {
		gFilterTable.dispose();
	}
}
