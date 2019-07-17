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
package docking.widgets.pathmanager;

import java.awt.Rectangle;
import java.util.ArrayList;

import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;

class PathnameTableModel extends AbstractTableModel {
	private static final long serialVersionUID = 1L;

	private ArrayList<String> pathList;
	private boolean isEditable;
	
	/**
	 * @param paths initial list of paths; may be null 
	 * @param isEditable true if the path should be editable
	 * 
	 */
	PathnameTableModel(String[] paths, boolean isEditable) {
		super();
		this.isEditable = isEditable;
		pathList = new ArrayList<String>();
		if (paths != null) {
			for (int i=0; i<paths.length; i++) {
				pathList.add(paths[i]);
			}
		}
	}

	public int getColumnCount() {
		return 1;
	}

	@Override
    public Class<String> getColumnClass(int columnIndex) {
		return String.class;
	}

	@Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
		return isEditable;
	}

	@Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		pathList.remove(rowIndex);
		pathList.add(rowIndex, aValue.toString());
		super.fireTableCellUpdated(rowIndex, 0);
	}

	public int getRowCount() {
		return pathList.size();
	}

	public Object getValueAt(int rowIndex, int columnIndex) {
		if (rowIndex >= pathList.size()) {
			return null;
		}
		return pathList.get(rowIndex);
	}

	void setEditingEnabled(boolean isEditable) {
		this.isEditable = isEditable;
	}
	
	void remove(int[] selectedRows) {
		String[] paths = new String[selectedRows.length];
		for (int i=0; i<selectedRows.length; i++) {
			paths[i] = pathList.get(selectedRows[i]);
		}
		
		for (int i=0; i<paths.length; i++) {
			pathList.remove(paths[i]);
		}
		fireTableDataChanged();
	}
	
	void moveUp(JTable table, int index) {
		if (index < 0 || index >= pathList.size()) {
			return;
		}
		String path = pathList.remove(index);
		int newIndex=0;
		if (index == 0) {
			// place it last in the list
			pathList.add(path);
			newIndex = pathList.size()-1;
		}
		else {
			newIndex = index-1;
			pathList.add(newIndex, path);
		}
		notifyDataChanged(table, newIndex);
	}

	void moveDown(JTable table, int index) {
		if (index < 0 || index >= pathList.size()) {
			return;
		}
		int size = pathList.size();
		int newIndex=0;
		String path = pathList.remove(index);
		if (index == size-1) {
			// move to the top of the list
			pathList.add(0, path);
		}
		else {
			newIndex = index+1;
			pathList.add(index+1, path);
		}
		notifyDataChanged(table, newIndex);
	}

	void addPaths(String[] paths, boolean addToTop) {
		for (int i=0;i<paths.length; i++) {
			if (!pathList.contains(paths[i])) {
				if (addToTop) {
					pathList.add(i, paths[i]);
				}
				else {
					pathList.add(paths[i]);
				}
			}
		}
		fireTableDataChanged();
	}

	void setPaths(String[] paths) {
		pathList.clear();
		addPaths(paths, false);
	}
	
	private void notifyDataChanged(JTable table, int newIndex) {
		fireTableDataChanged();
		table.setRowSelectionInterval(newIndex, newIndex);
		Rectangle rect = table.getCellRect(newIndex, 0, true);
		table.scrollRectToVisible(rect);
	}

}
