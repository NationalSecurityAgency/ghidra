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
package ghidra.app.plugin.core.datamgr;

import java.util.*;

import docking.widgets.table.AbstractSortedTableModel;
import ghidra.util.SystemUtilities;

/**
 * Table model for showing data types that are out of sync with an archive. It can be used
 * to either Commit or Update data types.
 * <br>Committing means overwriting the source data type in an archive with its associated
 * program data type that has been changed.
 * <br>Updating means overwriting the program data type with its associated archive data
 * type that has been changed.
 * <br>Currently the user can select which data types are to be synchronized
 * (committed back to the archive or updated in the program).
 */
class DataTypeSyncTableModel extends AbstractSortedTableModel<RowData> {

	final static int CHECKED_COL = 0;
	final static int STATUS_COL = 1;
	final static int NAME_COL = 2;
	final static int REF_PATH_COL = 3;
	final static int CHANGE_TIME_COL = 4;

	private String[] columnNames =
		new String[] { "Apply", "Status", "Datatype", "Category Path", "Change Time", };

	private final List<RowData> rowDataList;
	private final boolean showSourceChangeTime;

	/**
	 * Constructs a table model for synchronizing (committing or updating) data types between a
	 * program and an archive.
	 * @param list the list of data types to display.
	 * @param commit true means Commit, false means Update.
	 */
	DataTypeSyncTableModel(List<DataTypeSyncInfo> list, Set<DataTypeSyncInfo> preselectedInfos,
			boolean showSourceChangeTime) {
		this.showSourceChangeTime = showSourceChangeTime;
		this.rowDataList = new ArrayList<>(list.size());
		for (DataTypeSyncInfo dataTypeSyncInfo : list) {
			rowDataList.add(
				new RowData(dataTypeSyncInfo, preselectedInfos.contains(dataTypeSyncInfo)));
		}
	}

	@Override
	public String getName() {
		return "Datatype Sync";
	}

	@Override
	public int getRowCount() {
		return rowDataList.size();
	}

	@Override
	public int getColumnCount() {
		return columnNames.length;
	}

	@Override
	public Object getColumnValueForRow(RowData rowData, int columnIndex) {
		DataTypeSyncInfo syncInfo = rowData.syncInfo;
		switch (columnIndex) {
			case CHECKED_COL:
				return rowData.isSelected();
			case STATUS_COL:
				return syncInfo.getSyncState();
			case NAME_COL:
				return syncInfo.getName();
			case CHANGE_TIME_COL:
				return syncInfo.getLastChangeTimeString(showSourceChangeTime);
			case REF_PATH_COL:
				return syncInfo.getRefDtPath();
		}
		return null;
	}

	@Override
	public List<RowData> getModelData() {
		return rowDataList;
	}

	@Override
	public void setValueAt(Object value, int rowIndex, int columnIndex) {
		if (columnIndex == CHECKED_COL) {
			rowDataList.get(rowIndex).setSelected((Boolean) value);
		}
		fireTableRowsUpdated(rowIndex, rowIndex);
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if (columnIndex == CHECKED_COL) {
			return Boolean.class;
		}
		else if (columnIndex == STATUS_COL) {
			return DataTypeSyncState.class;
		}
		return String.class;
	}

	@Override
	public String getColumnName(int column) {
		return columnNames[column];
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return columnIndex == CHECKED_COL;
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	public DataTypeSyncInfo getSyncInfo(int selectedIndex) {
		return rowDataList.get(selectedIndex).syncInfo;
	}

	public void selectAll() {
		for (RowData rowData : rowDataList) {
			rowData.setSelected(true);
		}
		fireTableDataChanged();
	}

	public void deselectAll() {
		for (RowData rowData : rowDataList) {
			rowData.setSelected(false);
		}
		fireTableDataChanged();
	}

	public boolean hasUnresolvedDataTypes() {
		for (RowData rowData : rowDataList) {
			if (!rowData.isSelected()) {
				return true;
			}
		}
		return false;
	}

	public List<DataTypeSyncInfo> getSelectedItems() {
		List<DataTypeSyncInfo> selectedItems = new ArrayList<>();
		Iterator<RowData> iterator = rowDataList.iterator();
		while (iterator.hasNext()) {
			RowData rowData = iterator.next();
			if (rowData.isSelected()) {
				selectedItems.add(rowData.syncInfo);
			}
		}
		return selectedItems;
	}

	@Override
	protected Comparator<RowData> createSortComparator(int columnIndex) {
		return new RowDataSorter(columnIndex);
	}

	class RowDataSorter implements Comparator<RowData> {

		private final int sortColumn;

		public RowDataSorter(int sortColumn) {
			this.sortColumn = sortColumn;
		}

		@Override
		public int compare(RowData rowData1, RowData rowData2) {
			int compareVal = 0;
			DataTypeSyncInfo syncInfo1 = rowData1.syncInfo;
			DataTypeSyncInfo syncInfo2 = rowData2.syncInfo;
			switch (sortColumn) {
				case CHECKED_COL:
					compareVal = compareState(rowData1.isSelected(), rowData2.isSelected());
					break;
				case STATUS_COL:
					compareVal = SystemUtilities.compareTo(syncInfo1.getSyncState(),
						syncInfo2.getSyncState());
					break;
				case NAME_COL:
					compareVal = syncInfo1.getName().compareTo(syncInfo2.getName());
					break;
				case REF_PATH_COL:
					compareVal = syncInfo1.getRefDtPath().compareTo(syncInfo2.getRefDtPath());
					break;
				case CHANGE_TIME_COL:
					compareVal = compareDates(syncInfo1.getLastChangeTime(showSourceChangeTime),
						syncInfo2.getLastChangeTime(showSourceChangeTime));
					break;
			}
			return compareVal;
		}

		private int compareState(boolean can1, boolean can2) {
			if (can1 == can2) {
				return 0;
			}
			return can1 ? -1 : 1;
		}

		private int compareDates(long date1, long date2) {
			if (date1 < date2) {
				return -1;
			}
			if (date1 > date2) {
				return 1;
			}
			return 0;
		}
	}

}

class RowData {
	DataTypeSyncInfo syncInfo;
	private boolean selected;

	RowData(DataTypeSyncInfo syncInfo, boolean select) {
		this.syncInfo = syncInfo;
		this.selected = select;
	}

	void setSelected(boolean select) {
		this.selected = select;
	}

	boolean isSelected() {
		return selected;
	}
}
