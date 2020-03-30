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
import java.util.stream.Collectors;

import org.osgi.framework.*;

import docking.widgets.table.AbstractSortedTableModel;
import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.osgi.BundleHost;
import ghidra.app.script.osgi.SourceBundleInfo;
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
			return false;
		}

		Object getValue(BundlePath path) {
			return null;
		}

		void setValue(BundlePath path, Object aValue) {
			throw new RuntimeException(name + " is not editable!");
		}

	}

	Column enabledColumn = new Column("Enabled", Boolean.class) {
		@Override
		boolean editable(BundlePath path) {
			return path.exists();
		}

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
		boolean editable(BundlePath path) {
			return path.exists(); // XXX maybe only if it's already enabled
		}

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
			return false;
		}

		@Override
		Object getValue(BundlePath path) {
			return path;
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
	private List<BundlePath> paths;
	private BundleHost bundleHost;
	BundleListener bundleListener;

	private Map<String, BundlePath> loc2bp = new HashMap<>();

	BundlePath getPath(String bundleLocation) {
		return loc2bp.get(bundleLocation);
	}

	public String getBundleLoc(BundlePath bp) {
		switch (bp.getType()) {
			case Jar:
				return bp.getPath().getAbsolutePath();
			case SourceDir:
				SourceBundleInfo bi = bundleHost.getSourceBundleInfo(bp.getPath());
				return bi.getBundleLoc();
			case BndScript:
				// XXX 
			case INVALID:
			default:
				break;
		}
		return null;
	}

	/** 
	 * (re)compute cached mapping from bundleloc to bundlepath
	 */
	private void computeCache() {
		loc2bp.clear();
		for (BundlePath bp : paths) {
			String loc = getBundleLoc(bp);
			if (loc != null) {
				loc2bp.put(loc, bp);
			}
		}
	}

	BundleStatusModel(BundleStatusProvider provider, BundleHost bundleHost) {
		super();
		this.provider = provider;
		this.bundleHost = bundleHost;

		// add unmodifiable paths
		this.paths = GhidraScriptUtil.getSystemScriptPaths().stream().distinct().map(
			f -> new BundlePath(f, true, true)).collect(Collectors.toList());
		// add user path
		this.paths.add(0, new BundlePath(GhidraScriptUtil.getUserScriptDirectory(), true, false));
		computeCache();

		bundleHost.addListener(bundleListener = new BundleListener() {
			@Override
			public void bundleChanged(BundleEvent event) {
				Bundle b = event.getBundle();
				BundlePath bp;
				switch (event.getType()) {
					case BundleEvent.INSTALLED:
					case BundleEvent.LAZY_ACTIVATION:
					case BundleEvent.RESOLVED:
					case BundleEvent.STARTING:
					case BundleEvent.STOPPED:
					case BundleEvent.STOPPING:
					case BundleEvent.UNRESOLVED:
					case BundleEvent.UPDATED:
						break;
					case BundleEvent.STARTED:
						bp = getPath(b.getLocation());
						if (bp != null) {
							bp.setActive(true);
							int row = getRowIndex(bp);
							fireTableRowsUpdated(row, row);
						}
						break;
					case BundleEvent.UNINSTALLED:
						bp = getPath(b.getLocation());
						if (bp != null) {
							bp.setActive(false);
							int row = getRowIndex(bp);
							fireTableRowsUpdated(row, row);
						}
						break;
					default:
						System.err.printf("What is a %d event??", event.getType());
						break;
				}
			}
		});

		fireTableDataChanged();
	}

	@Override
	public void dispose() {
		super.dispose();
		bundleHost.removeListener(bundleListener);
	}

	void clear() {
		paths.clear();
	}

	List<BundlePath> getAllPaths() {
		return new ArrayList<BundlePath>(paths);
	}

	public List<ResourceFile> getPaths() {
		List<ResourceFile> list = new ArrayList<>();
		for (BundlePath path : paths) {
			if (path.isEnabled()) {
				list.add(path.getPath());
			}
		}
		return list;
	}

	private void addPath(BundlePath path) {
		if (paths.contains(path)) {
			return;
		}
		String loc = getBundleLoc(path);
		if (loc != null) {
			loc2bp.put(loc, path);
		}

		int index = paths.size();
		paths.add(path);
		fireTableRowsInserted(index, index);
	}

	BundlePath addNewPath(ResourceFile path, boolean enabled, boolean readonly) {
		BundlePath p = new BundlePath(path, enabled, readonly);
		addPath(p);
		return p;
	}

	BundlePath addNewPath(String path, boolean enabled, boolean readonly) {
		BundlePath p = new BundlePath(path, enabled, readonly);
		addPath(p);
		return p;
	}

	void remove(int[] selectedRows) {
		List<BundlePath> list = new ArrayList<>();
		for (int selectedRow : selectedRows) {
			list.add(paths.get(selectedRow));
		}
		for (BundlePath path : list) {
			if (!path.isReadOnly()) {
				paths.remove(path);
				loc2bp.remove(getBundleLoc(path));
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
		addNewPath(dir, true, false);
		Preferences.setProperty(BundleStatusProvider.preferenceForLastSelectedBundle,
			dir.getAbsolutePath());
		provider.fireBundlesChanged();
		return true;
	}

	/**
	 * Test whether the given <code>bundle</code> is managed and not marked readonly
	 * @param bundle the path to test 
	 * @return true if the bundle is managed and not marked readonly
	 */
	public boolean isWriteable(ResourceFile bundle) {
		Optional<BundlePath> o = paths.stream().filter(
			bp -> bp.isDirectory() && bp.getPath().equals(bundle)).findFirst();
		return o.isPresent() && !o.get().isReadOnly();
	}

	/**
	 * This is for testing only!
	 * 
	 * each path is marked editable and non-readonly
	 * 
	 * @param testingPaths the paths to use
	 */
	public void setPathsForTesting(List<String> testingPaths) {
		this.paths = testingPaths.stream().map(f -> new BundlePath(f, true, false)).collect(
			Collectors.toList());
		computeCache();
		fireTableDataChanged();
	}

	/**
	 * This is for testing only!
	 * 
	 * insert path, marked editable and non-readonly
	 * @param path the path to insert
	 */
	public void insertPathForTesting(String path) {
		addNewPath(path, true, false);
	}

}
