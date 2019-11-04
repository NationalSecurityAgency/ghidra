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
import docking.widgets.table.TableSortState;
import ghidra.framework.store.Version;

/**
 * Table model for showing version history.
 */
class VersionHistoryTableModel extends AbstractSortedTableModel<Version> {

	final static String DATE = "Version Date";
	final static String VERSION = "Version";
	final static String USER = "User";
	final static String COMMENTS = "Comments";

	// columns used in the getValueAt() method
	final static int VERSION_COL = 0;
	final static int DATE_COL = 1;
	final static int USER_COL = 2;
	final static int COMMENTS_COL = 3;

	private String[] columnNames = { VERSION, DATE, USER, COMMENTS };

	private List<Version> versionList;

	VersionHistoryTableModel(Version[] versions) {
		versionList = new ArrayList<>();
		for (Version version : versions) {
			versionList.add(version);
		}
		setDefaultTableSortState(TableSortState.createDefaultSortState(VERSION_COL, false));
	}

	@Override
	public String getName() {
		return "Version History";
	}

	@Override
	public int getColumnCount() {
		return columnNames.length;
	}

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

	@Override
	public String getColumnName(int column) {
		return columnNames[column];
	}

	void refresh(Version[] newVersions) {
		List<Version> newVersionList = new ArrayList<>();
		for (Version version : newVersions) {
			newVersionList.add(version);
		}
		versionList = newVersionList;
		fireTableDataChanged();
	}

	Version getVersionAt(int row) {
		if (row < 0 || row >= versionList.size()) {
			return null;
		}
		return versionList.get(row);
	}

	@Override
	public Object getColumnValueForRow(Version version, int columnIndex) {
		switch (columnIndex) {
			case VERSION_COL:
				return version.getVersion();
			case DATE_COL:
				return new Date(version.getCreateTime());
			case USER_COL:
				return version.getUser();
			case COMMENTS_COL:
				return version.getComment();
		}
		return null;
	}

	@Override
	public List<Version> getModelData() {
		return versionList;
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

}
