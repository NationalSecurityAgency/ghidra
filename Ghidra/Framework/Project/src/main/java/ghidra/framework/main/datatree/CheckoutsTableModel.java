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
package ghidra.framework.main.datatree;

import java.util.*;

import docking.widgets.table.AbstractSortedTableModel;
import ghidra.framework.store.ItemCheckoutStatus;

/**
 * Table model for showing checkout information for a domain file.
 *
 *
 */
class CheckoutsTableModel extends AbstractSortedTableModel<ItemCheckoutStatus> {
	private static final long serialVersionUID = 1L;

	final static String DATE = "Checkout Date";
	final static String VERSION = "Version";
	final static String USER = "User";
	final static String HOST = "Hostname";
	final static String PROJECT_NAME = "Project Name";
	final static String PROJECT_LOC = "Location";

	// columns used in the getValueAt() method
	final static int DATE_COL = 0;
	final static int VERSION_COL = 1;
	final static int USER_COL = 2;
	final static int HOST_COL = 3;
	final static int PROJECT_NAME_COL = 4;
	final static int PROJECT_LOC_COL = 5;

	private String[] columnNames = { DATE, VERSION, USER, HOST, PROJECT_NAME, PROJECT_LOC };

	private ItemCheckoutStatus[] statusItems;

	CheckoutsTableModel(ItemCheckoutStatus[] status) {
		this.statusItems = status;
	}

	@Override
	public String getName() {
		return "Checkouts";
	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#getColumnCount()
	 */
	@Override
	public int getColumnCount() {
		return columnNames.length;
	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#getRowCount()
	 */
	@Override
	public int getRowCount() {
		if (statusItems != null) {
			return statusItems.length;
		}
		return 0;
	}

	/* (non Javadoc)
	 * @see javax.swing.table.TableModel#getColumnClass(int)
	 */
	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if (columnIndex == DATE_COL) {
			return Date.class;
		}
		if (columnIndex == VERSION_COL) {
			return Integer.class;
		}
		return String.class;
	}

	/* (non Javadoc)
	 * @see javax.swing.table.TableModel#getColumnName(int)
	 */
	@Override
	public String getColumnName(int column) {
		return columnNames[column];
	}

	/* (non Javadoc)
	 * @see javax.swing.table.TableModel#isCellEditable(int, int)
	 */
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return false;
	}

	/**
	 * @param statuses
	 */
	void refresh(ItemCheckoutStatus[] status) {
		this.statusItems = status;
		fireTableDataChanged();
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public List<ItemCheckoutStatus> getModelData() {
		return Arrays.asList(statusItems);
	}

	@Override
	public Object getColumnValueForRow(ItemCheckoutStatus t, int columnIndex) {
		switch (columnIndex) {
			case DATE_COL:
				return new Date(t.getCheckoutTime());
			case VERSION_COL:
				return new Integer(t.getCheckoutVersion());
			case USER_COL:
				return t.getUser();
			case HOST_COL:
				return t.getUserHostName();
			case PROJECT_NAME_COL:
				String name = t.getProjectName();
				return name != null ? name : "";
			case PROJECT_LOC_COL:
				String location = t.getProjectLocation();
				return location != null ? location : "";
		}
		return null;
	}
}
