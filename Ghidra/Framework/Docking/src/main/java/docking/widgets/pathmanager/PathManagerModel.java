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

import generic.util.Path;

import java.util.ArrayList;
import java.util.List;

import javax.swing.table.AbstractTableModel;

class PathManagerModel extends AbstractTableModel {

	final static int COLUMN_USE = 0;
	final static int COLUMN_PATH = 1;

	private PathManager mgr;
	private List<Path> paths = new ArrayList<Path>();

	PathManagerModel(PathManager mgr, List<Path> paths) {
		super();
		this.mgr = mgr;
		this.paths.addAll(dedupPaths(paths));
		fireTableDataChanged();
	}

	private List<Path> dedupPaths(List<Path> newPaths) {
		List<Path> dedupedPaths = new ArrayList<Path>();
		for (Path path : newPaths) {
			if (!dedupedPaths.contains(path)) {
				dedupedPaths.add(path);
			}
		}
		return dedupedPaths;
	}

	void clear() {
		paths.clear();
	}

	List<Path> getAllPaths() {
		return new ArrayList<Path>(paths);
	}

	List<Path> getPaths() {
		List<Path> list = new ArrayList<Path>();
		for (Path path : paths) {
			if (path.isEnabled()) {
				list.add(path);
			}
		}
		return list;
	}

	void setPaths(List<Path> paths) {
		this.paths = new ArrayList<Path>(paths);
		fireTableDataChanged();
	}

	void setPaths(Path[] pathsArr) {
		paths.clear();
		paths = new ArrayList<Path>();
		for (int i = 0; i < pathsArr.length; i++) {
			paths.add(pathsArr[i]);
		}
		fireTableDataChanged();
	}

	void addPath(Path path, boolean addToTop) {
		if (paths.contains(path)) {
			return;
		}
		if (addToTop) {
			paths.add(0, path);
			fireTableRowsInserted(0, 0);
		}
		else {
			int index = paths.size();
			paths.add(path);
			fireTableRowsInserted(index, index);
		}
	}

	void removePath(Path path) {
		int index = paths.indexOf(path);
		if (path.isEditable()) {
			paths.remove(path);
		}
		else {
			List<PathManagerListener> listeners = mgr.getListeners();
			for (PathManagerListener listener : listeners) {
				listener.pathMessage("Unable to remove path.");
			}
		}
		fireTableRowsDeleted(index, index);
	}

	void remove(int[] selectedRows) {
		List<Path> list = new ArrayList<Path>();
		for (int i = 0; i < selectedRows.length; i++) {
			list.add(paths.get(selectedRows[i]));
		}
		for (Path path : list) {
			if (path.isEditable()) {
				paths.remove(path);
			}
			else {
				List<PathManagerListener> listeners = mgr.getListeners();
				for (PathManagerListener listener : listeners) {
					listener.pathMessage("Unable to remove path.");
				}
			}
		}
		fireTableDataChanged();
	}

	int moveUp(int index) {
		if (index < 0 || index >= paths.size()) {
			return -1;
		}
		Path path = paths.remove(index);
		if (index == 0) {
			paths.add(path);//place it last in the list
		}
		else {
			paths.add(index - 1, path);
		}
		fireTableDataChanged();
		return paths.indexOf(path);
	}

	int moveDown(int index) {
		if (index < 0 || index >= paths.size()) {
			return -1;
		}
		int size = paths.size();
		Path path = paths.remove(index);
		if (index == size - 1) {
			paths.add(0, path);//move to the top of the list
		}
		else {
			paths.add(index + 1, path);
		}
		fireTableDataChanged();
		return paths.indexOf(path);
	}

	/***************************************************/

	@Override
	public java.lang.Class<?> getColumnClass(int columnIndex) {
		switch (columnIndex) {
			case COLUMN_USE:
				return Boolean.class;
			case COLUMN_PATH:
				return Path.class;
		}
		return Object.class;
	}

	@Override
	public int getColumnCount() {
		return 2;
	}

	@Override
	public int getRowCount() {
		return paths.size();
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		Path path = paths.get(rowIndex);
		switch (columnIndex) {
			case COLUMN_USE:
				return true;
			case COLUMN_PATH:
				return path.isEditable();
		}
		return true;
	}

	@Override
	public String getColumnName(int columnIndex) {
		switch (columnIndex) {
			case COLUMN_USE:
				return "Use";
			case COLUMN_PATH:
				return "Path";
		}
		return null;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		Path path = paths.get(rowIndex);
		switch (columnIndex) {
			case COLUMN_USE:
				return path.isEnabled();
			case COLUMN_PATH:
				return path;
		}
		return null;
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		Path path = paths.get(rowIndex);
		switch (columnIndex) {
			case COLUMN_USE:
				path.setEnabled((Boolean) aValue);
				break;
			case COLUMN_PATH:
				if (path.isEditable()) {
					Path newpath = (Path) aValue;
					path.setPath(newpath.getPath());
				}
				break;
		}
		fireTableDataChanged();
	}
}
