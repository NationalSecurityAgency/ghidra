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

import java.util.ArrayList;
import java.util.List;

import docking.widgets.table.AbstractSortedTableModel;
import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;

public class BundleStatusModel extends AbstractSortedTableModel<BundlePath> {
	List<Column> columns = new ArrayList<>();

	class Column {
		final Class<?> clazz;
		final int index;
		final String name;

		Column(String name, Class<?> clazz) {
			this.name = name;
			this.index = columns.size();
			columns.add(this);
			this.clazz = clazz;
		}

		boolean editable(BundlePath path) {
			return true;
		}

		Object getValue(BundlePath path) {
			return path;
		}

		void setValue(BundlePath path, Object aValue) {
			// do nothing
		}

	}

	Column enabledColumn = new Column("Enabled", Boolean.class) {
		@Override
		Object getValue(BundlePath path) {
			return path.isEnabled();
		}

		@Override
		void setValue(BundlePath path, Object newValue) {
			path.setEnabled((Boolean) newValue);
			provider.fireBundleEnablementChanged(path, (Boolean) newValue);
		}
	};
	Column activeColumn = new Column("Active", Boolean.class) {
		@Override
		Object getValue(BundlePath path) {
			return path.isActive();
		}

		@Override
		void setValue(BundlePath path, Object newValue) {
			path.setActive((Boolean) newValue);
			provider.fireBundleActivationChanged(path, (Boolean) newValue);
		}
	};
	Column typeColumn = new Column("Type", String.class) {
		@Override
		boolean editable(BundlePath path) {
			return false;
		}

		@Override
		Object getValue(BundlePath path) {
			return path.getType().toString();
		}
	};

	Column pathColumn = new Column("Path", BundlePath.class) {
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
	};
	Column badColumn = new Column("INVALID", Object.class);
	{
		columns.remove(columns.size() - 1); // pop badColumn

	}

	Column getColumn(int i) {
		if (i >= 0 && i < columns.size()) {
			return columns.get(i);
		}
		return badColumn;
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

	public List<BundlePath> getPaths() {
		List<BundlePath> list = new ArrayList<>();
		for (BundlePath path : paths) {
			if (path.isEnabled()) {
				list.add(path);
			}
		}
		return list;
	}

	public void setPaths(List<BundlePath> paths) {
		this.paths = new ArrayList<>(paths);
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
				Msg.showInfo(this, this.provider.getComponent(), "Unabled to remove path",
					"System path cannot be removed: " + path.toString());
			}
		}
		fireTableDataChanged();
	}

	/***************************************************/

	@Override
	public int getColumnCount() {
		return columns.size();
	}

	@Override
	public int getRowCount() {
		return paths.size();
	}

	@Override
	public java.lang.Class<?> getColumnClass(int columnIndex) {
		return getColumn(columnIndex).clazz;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		BundlePath path = paths.get(rowIndex);
		return getColumn(columnIndex).editable(path);
	}

	@Override
	public String getColumnName(int columnIndex) {
		return getColumn(columnIndex).name;
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		BundlePath path = paths.get(rowIndex);
		getColumn(columnIndex).setValue(path, aValue);
	}

	@Override
	public Object getColumnValueForRow(BundlePath path, int columnIndex) {
		return getColumn(columnIndex).getValue(path);
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

	/**
	 * (add and) enable a path
	 * @param file path to enable 
	 * @return true if the path is new
	 */
	public boolean enablePath(ResourceFile file) {
		ResourceFile dir = file.isDirectory() ? file : file.getParentFile();
		for (BundlePath path : getAllPaths()) {
			if (path.getPath().equals(dir)) {
				if (!path.isEnabled()) {
					path.setEnabled(true);
					fireTableDataChanged();
					provider.fireBundlesChanged();
					return true;
				}
				return false;
			}
		}
		BundlePath p = new BundlePath(dir);
		p.setEnabled(true);
		addPath(p);
		Preferences.setProperty(BundleStatusProvider.preferenceForLastSelectedBundle, dir.getAbsolutePath());
		provider.fireBundlesChanged();
		return true;
	}
}
