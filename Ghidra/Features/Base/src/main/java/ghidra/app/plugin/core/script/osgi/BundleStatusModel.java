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
package ghidra.app.plugin.core.script.osgi;

import java.util.*;

import docking.widgets.table.AbstractSortedTableModel;
import ghidra.app.script.GhidraScriptUtil;

class BundleStatusModel extends AbstractSortedTableModel<BundlePath> {
	private static int column_counter = 0;

	static enum COLUMN {
		Enabled(Boolean.class) {
			@Override
			Object getValue(BundlePath path) {
				return path.isEnabled();
			}

			@Override
			void setValue(BundlePath path, Object aValue) {
				path.setEnabled((Boolean) aValue);
			}
		},
		Active(Boolean.class) {
			@Override
			Object getValue(BundlePath path) {
				return path.isActive();
			}

			@Override
			void setValue(BundlePath path, Object aValue) {
				path.setActive((Boolean) aValue);
			}
		},
		Type(String.class) {
			@Override
			boolean editable(BundlePath path) {
				return false;
			}

			@Override
			Object getValue(BundlePath path) {
				return path.getType().toString();
			}

		},
		Path(BundlePath.class) {
			@Override
			boolean editable(BundlePath path) {
				return true;
			}

			@Override
			void setValue(BundlePath path, Object aValue) {
				if (path.isEditable()) {
					BundlePath newpath = (BundlePath) aValue;
					path.setPath(newpath.getPath());
				}
			}
		},
		__badcolumnindex__(Object.class);

		final Class<?> clazz;
		final int index;

		boolean editable(BundlePath path) {
			return true;
		}

		Object getValue(BundlePath path) {
			return path;
		}

		COLUMN(Class<?> clazz) {
			this.index = column_counter++;
			this.clazz = clazz;
		}

		static COLUMN[] vals = values();
		static {
			vals = Arrays.copyOf(vals, vals.length - 1);
		}

		static COLUMN val(int i) {
			if (i >= 0 && i < vals.length) {
				return vals[i];
			}
			return __badcolumnindex__;
		}

		void setValue(BundlePath path, Object aValue) {
			// do nothing
		}
	}

	private BundleStatusProvider provider;
	private List<BundlePath> paths = new ArrayList<>();

	BundleStatusModel(BundleStatusProvider provider) {
		super();
		this.provider = provider;
		this.paths.addAll(dedupPaths(GhidraScriptUtil.getDefaultScriptBundles()));
		fireTableDataChanged();
	}

	private List<BundlePath> dedupPaths(List<BundlePath> newPaths) {
		List<BundlePath> dedupedPaths = new ArrayList<>();
		for (BundlePath path : newPaths) {
			if (!dedupedPaths.contains(path)) {
				dedupedPaths.add(path);
			}
		}
		return dedupedPaths;
	}

	void clear() {
		paths.clear();
	}

	List<BundlePath> getAllPaths() {
		return new ArrayList<BundlePath>(paths);
	}

	List<BundlePath> getPaths() {
		List<BundlePath> list = new ArrayList<>();
		for (BundlePath path : paths) {
			if (path.isEnabled()) {
				list.add(path);
			}
		}
		return list;
	}

	void setPaths(List<BundlePath> paths) {
		this.paths = new ArrayList<>(paths);
		fireTableDataChanged();
	}

	void setPaths(BundlePath[] pathsArr) {
		paths.clear();
		paths = new ArrayList<>();
		for (BundlePath element : pathsArr) {
			paths.add(element);
		}
		fireTableDataChanged();
	}

	void addPath(BundlePath path) {
		if (paths.contains(path)) {
			return;
		}
		int index = paths.size();
		paths.add(path);
		fireTableRowsInserted(index, index);
	}

	void removePath(BundlePath path) {
		int index = paths.indexOf(path);
		if (path.isEditable()) {
			paths.remove(path);
		}
		else {
			List<BundlePathManagerListener> listeners = provider.getListeners();
			for (BundlePathManagerListener listener : listeners) {
				listener.pathMessage("Unable to remove path.");
			}
		}
		fireTableRowsDeleted(index, index);
	}

	void remove(int[] selectedRows) {
		List<BundlePath> list = new ArrayList<>();
		for (int selectedRow : selectedRows) {
			list.add(paths.get(selectedRow));
		}
		for (BundlePath path : list) {
			if (path.isEditable()) {
				paths.remove(path);
			}
			else {
				List<BundlePathManagerListener> listeners = provider.getListeners();
				for (BundlePathManagerListener listener : listeners) {
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
		BundlePath path = paths.remove(index);
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
		BundlePath path = paths.remove(index);
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
		return COLUMN.val(columnIndex).clazz;
	}

	@Override
	public int getColumnCount() {
		return COLUMN.vals.length;
	}

	@Override
	public int getRowCount() {
		return paths.size();
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		BundlePath path = paths.get(rowIndex);
		return COLUMN.val(columnIndex).editable(path);
	}

	@Override
	public String getColumnName(int columnIndex) {
		return COLUMN.val(columnIndex).toString();
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		BundlePath path = paths.get(rowIndex);
		COLUMN.val(columnIndex).setValue(path, aValue);
		fireTableDataChanged();
		provider.fireBundlePathChanged(path);
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public String getName() {
		return "BundlePathManagerModel";
	}

	@Override
	public List<BundlePath> getModelData() {
		return paths;
	}

	@Override
	public Object getColumnValueForRow(BundlePath path, int columnIndex) {
		return COLUMN.val(columnIndex).getValue(path);
	}
}
