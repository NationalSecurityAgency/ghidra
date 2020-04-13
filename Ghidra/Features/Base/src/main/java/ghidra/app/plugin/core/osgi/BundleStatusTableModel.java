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
package ghidra.app.plugin.core.osgi;

import java.io.File;
import java.util.*;
import java.util.stream.Collectors;

import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.TableSortingContext;
import generic.jar.ResourceFile;
import ghidra.util.Msg;

public class BundleStatusTableModel extends AbstractSortedTableModel<BundleStatus> {
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

		boolean editable(BundleStatus status) {
			return false;
		}

		Object getValue(BundleStatus status) {
			return null;
		}

		void setValue(BundleStatus status, Object aValue) {
			throw new RuntimeException(name + " is not editable!");
		}

	}

	Column enabledColumn = new Column("Enabled", Boolean.class) {
		@Override
		boolean editable(BundleStatus status) {
			return status.pathExists();
		}

		@Override
		Object getValue(BundleStatus status) {
			return status.isEnabled();
		}

		@Override
		void setValue(BundleStatus status, Object newValue) {
			fireBundleEnablementChangeRequested(status, (Boolean) newValue);
		}
	};
	Column activeColumn = new Column("Active", Boolean.class) {
		@Override
		boolean editable(BundleStatus status) {
			return status.pathExists(); // XXX maybe only if it's already enabled
		}

		@Override
		Object getValue(BundleStatus status) {
			return status.isActive();
		}

		@Override
		void setValue(BundleStatus status, Object newValue) {
			status.setActive((Boolean) newValue);
			fireBundleActivationChangeRequested(status, (Boolean) newValue);
		}
	};
	Column typeColumn = new Column("Type", String.class) {
		@Override
		Object getValue(BundleStatus status) {
			return status.getType().toString();
		}
	};

	Column pathColumn = new Column("Path", ResourceFile.class) {
		@Override
		Object getValue(BundleStatus status) {
			return status.getPath();
		}
	};
	Column summaryColumn = new Column("Summary", String.class) {
		@Override
		Object getValue(BundleStatus status) {
			return status.getSummary();
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

	private BundleStatusComponentProvider provider;
	private List<BundleStatus> statuses;
	private BundleHost bundleHost;
	BundleHostListener bundleListener;

	private Map<String, BundleStatus> loc2status = new HashMap<>();

	BundleStatus getStatus(GhidraBundle gb) {
		BundleStatus status = loc2status.get(gb.getBundleLoc());
		if (status == null) {
			Msg.showError(BundleStatusTableModel.this, provider.getComponent(), "bundle status error",
				"bundle has no status!");
		}
		return status;
	}

	public String getBundleLoc(BundleStatus status) {
		GhidraBundle gb = bundleHost.getExistingGhidraBundle(status.getPath());
		if (gb != null) {
			return gb.getBundleLoc();
		}
		return null;
	}

	/** 
	 * (re)compute cached mapping from bundleloc to bundlepath
	 */
	private void computeCache() {
		loc2status.clear();
		for (BundleStatus status : statuses) {
			String loc = getBundleLoc(status);
			if (loc != null) {
				loc2status.put(loc, status);
			}
		}
	}

	BundleStatusTableModel(BundleStatusComponentProvider provider, BundleHost bundleHost) {
		super();
		this.provider = provider;
		this.bundleHost = bundleHost;
		statuses = new ArrayList<>();

		bundleHost.addListener(bundleListener = new BundleHostListener() {
			@Override
			public void bundleBuilt(GhidraBundle gb) {
				BundleStatus status = getStatus(gb);
				status.setSummary(gb.getSummary());
				int row = getRowIndex(status);
				fireTableRowsUpdated(row, row);
			}

			@Override
			public void bundleActivationChange(GhidraBundle gb, boolean newActivation) {
				BundleStatus status = getStatus(gb);
				int row = getRowIndex(status);
				if (newActivation) {
					status.setActive(true);
					status.setSummary(gb.getSummary());
				}
				else {
					status.setActive(false);
					status.setSummary("");
				}
				fireTableRowsUpdated(row, row);
			}

			@Override
			public void bundleAdded(GhidraBundle gb) {
				addNewStatus(gb.getPath(), gb.isEnabled(), gb.isSystemBundle());
			}

			@Override
			public void bundlesAdded(Collection<GhidraBundle> gbundles) {
				int index = statuses.size();
				for (GhidraBundle gb : gbundles) {
					BundleStatus status =
						new BundleStatus(gb.getPath(), gb.isEnabled(), gb.isSystemBundle());
					addStatusNoFire(status);
				}
				fireTableRowsInserted(index, gbundles.size() - 1);
			}

			@Override
			public void bundleRemoved(GhidraBundle gbundle) {
				BundleStatus status = getStatus(gbundle);
				removeStatus(status);
			}

			@Override
			public void bundlesRemoved(Collection<GhidraBundle> gbundles) {
				List<BundleStatus> toRemove =
					gbundles.stream().map(BundleStatusTableModel.this::getStatus).collect(
						Collectors.toUnmodifiableList());
				removeStatuses(toRemove);
			}

			@Override
			public void bundleEnablementChange(GhidraBundle gbundle, boolean newEnablement) {
				BundleStatus status = getStatus(gbundle);
				status.setEnabled(newEnablement);
				int row = getRowIndex(status);
				fireTableRowsUpdated(row, row);
			}

		});
	}

	@Override
	public void dispose() {
		super.dispose();
		bundleHost.removeListener(bundleListener);
	}

	public List<ResourceFile> getEnabledPaths() {
		List<ResourceFile> list = new ArrayList<>();
		for (BundleStatus status : statuses) {
			if (status.isEnabled()) {
				list.add(status.getPath());
			}
		}
		return list;
	}

	private void addStatusNoFire(BundleStatus path) {
		if (statuses.contains(path)) {
			return;
		}
		String loc = getBundleLoc(path);
		if (loc != null) {
			loc2status.put(loc, path);
		}
		statuses.add(path);
	}

	/**
	 *  add new status and fire a table udpate
	 */
	private BundleStatus addNewStatus(ResourceFile path, boolean enabled, boolean readonly) {
		BundleStatus p = new BundleStatus(path, enabled, readonly);
		int index = statuses.size();
		addStatusNoFire(p);
		fireTableRowsInserted(index, index);
		return p;
	}

	/**
	 * create new BundleStatus objects for each of the given files
	 * 
	 * @param files the files.. given...
	 * @param enabled mark them all as enabled
	 * @param readonly mark them all as readonly
	 */
	void addNewStatuses(List<File> files, boolean enabled, boolean readonly) {
		int index = statuses.size();
		for (File f : files) {
			BundleStatus status = new BundleStatus(new ResourceFile(f), enabled, readonly);
			addStatusNoFire(status);
		}
		fireTableRowsInserted(index, files.size() - 1);
	}

	private int removeStatusNoFire(BundleStatus status) {
		if (!status.isReadOnly()) {
			int i = statuses.indexOf(status);
			loc2status.remove(getBundleLoc(status));
			return i;
		}
		Msg.showInfo(this, this.provider.getComponent(), "Unabled to remove path",
			"System path cannot be removed: " + status.getPath().toString());
		return -1;
	}

	void removeStatus(BundleStatus status) {
		int row = removeStatusNoFire(status);
		if (row >= 0) {
			fireTableRowsDeleted(row, row);
		}
	}

	void remove(int[] modelRows) {
		List<BundleStatus> toRemove = Arrays.stream(modelRows).mapToObj(statuses::get).collect(
			Collectors.toUnmodifiableList());
		removeStatuses(toRemove);
	}

	void removeStatuses(List<BundleStatus> toRemove) {
		for (BundleStatus status : toRemove) {
			removeStatusNoFire(status);
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
		return statuses.size();
	}

	@Override
	public java.lang.Class<?> getColumnClass(int columnIndex) {
		return getColumn(columnIndex).clazz;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		BundleStatus status = statuses.get(rowIndex);
		return getColumn(columnIndex).editable(status);
	}

	@Override
	public String getColumnName(int columnIndex) {
		return getColumn(columnIndex).name;
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		BundleStatus status = statuses.get(rowIndex);
		getColumn(columnIndex).setValue(status, aValue);
		// XXX I don't know why it's unselected, but it's maddening
		provider.selectModelRow(rowIndex);
	}

	@Override
	public Object getColumnValueForRow(BundleStatus status, int columnIndex) {
		return getColumn(columnIndex).getValue(status);
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public String getName() {
		return BundleStatusTableModel.class.getSimpleName();
	}

	@Override
	public List<BundleStatus> getModelData() {
		return statuses;
	}

	/**
	 * Test whether the given <code>bundle</code> is managed and not marked readonly
	 * @param bundle the path to test 
	 * @return true if the bundle is managed and not marked readonly
	 */
	public boolean isWriteable(ResourceFile bundle) {
		Optional<BundleStatus> o = statuses.stream().filter(
			status -> status.isDirectory() && status.getPath().equals(bundle)).findFirst();
		return o.isPresent() && !o.get().isReadOnly();
	}

	/**
	 * This is for testing only!
	 * 
	 * each path is marked editable and non-readonly
	 * 
	 * @param testingPaths the statuses to use
	 */
	public void setPathsForTesting(List<String> testingPaths) {
		this.statuses = testingPaths.stream().map(f -> new BundleStatus(f, true, false)).collect(
			Collectors.toList());
		computeCache();
		fireTableDataChanged();
	}

	private ArrayList<BundleStatusChangeRequestListener> bundleStatusListeners = new ArrayList<>();

	public void addListener(BundleStatusChangeRequestListener listener) {
		synchronized (bundleStatusListeners) {
			if (!bundleStatusListeners.contains(listener)) {
				bundleStatusListeners.add(listener);
			}
		}
	}

	public void removeListener(BundleStatusChangeRequestListener listener) {
		synchronized (bundleStatusListeners) {
			bundleStatusListeners.remove(listener);
		}
	}

	void fireBundleEnablementChangeRequested(BundleStatus path, boolean newValue) {
		synchronized (bundleStatusListeners) {
			for (BundleStatusChangeRequestListener listener : bundleStatusListeners) {
				listener.bundleEnablementChangeRequest(path, newValue);
			}
		}
	}

	void fireBundleActivationChangeRequested(BundleStatus path, boolean newValue) {
		synchronized (bundleStatusListeners) {
			for (BundleStatusChangeRequestListener listener : bundleStatusListeners) {
				listener.bundleActivationChangeRequest(path, newValue);
			}
		}
	}

	public List<BundleStatus> getRowObjects(int[] modelRowIndices) {
		List<BundleStatus> rows = new ArrayList<>(modelRowIndices.length);
		for (int i : modelRowIndices) {
			rows.add(getRowObject(i));
		}
		return rows;
	}

	/**
	 * overridden to avoid generating events when nothing changed 
	 */
	@Override
	protected void sort(List<BundleStatus> data, TableSortingContext<BundleStatus> sortingContext) {

		if (sortingContext.isUnsorted()) {
			// this is the 'no sort' state
			sortCompleted(sortingContext);
			notifyModelSorted(false);
			return;
		}

		hasEverSorted = true; // signal that we have sorted at least one time

		boolean[] change = { false };
		Comparator<BundleStatus> proxy = new Comparator<BundleStatus>() {
			Comparator<BundleStatus> p = sortingContext.getComparator();

			@Override
			public int compare(BundleStatus o1, BundleStatus o2) {
				int v = p.compare(o1, o2);
				if (v < 0) {
					change[0] = true;
				}
				return v;
			}
		};
		Collections.sort(data, proxy);
		sortCompleted(sortingContext);
		if (change[0]) {
			notifyModelSorted(false);
		}
	}

}
