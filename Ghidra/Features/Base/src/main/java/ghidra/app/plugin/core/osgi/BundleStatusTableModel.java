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
package ghidra.app.plugin.core.osgi;

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
		return getStatusFromLoc(gb.getBundleLoc());
	}

	BundleStatus getStatusFromLoc(String bundleLoc) {
		BundleStatus status = loc2status.get(bundleLoc);
		if (status == null) {
			Msg.showError(BundleStatusTableModel.this, provider.getComponent(),
				"bundle status error", "bundle has no status!");
		}
		return status;
	}

	BundleStatusTableModel(BundleStatusComponentProvider provider, BundleHost bundleHost) {
		super();
		this.provider = provider;
		this.bundleHost = bundleHost;
		statuses = new ArrayList<>();
		for (GhidraBundle gb : bundleHost.getGhidraBundles()) {
			addNewStatus(gb);
		}

		bundleHost.addListener(bundleListener = new BundleHostListener() {
			@Override
			public void bundleBuilt(GhidraBundle gb, String summary) {
				BundleStatus status = getStatus(gb);
				status.setSummary(summary);
				int row = getRowIndex(status);
				fireTableRowsUpdated(row, row);
			}

			@Override
			public void bundleActivationChange(GhidraBundle gb, boolean newActivation) {
				BundleStatus status = getStatus(gb);
				int row = getRowIndex(status);
				status.setBusy(false);
				if (newActivation) {
					status.setActive(true);
				}
				else {
					status.setActive(false);
				}
				fireTableRowsUpdated(row, row);
			}

			@Override
			public void bundleAdded(GhidraBundle gb) {
				addNewStatus(gb);
			}

			@Override
			public void bundlesAdded(Collection<GhidraBundle> gbundles) {
				int index = statuses.size();
				for (GhidraBundle gb : gbundles) {
					addNewStatusNoFire(gb);
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

			@Override
			public void bundleException(GhidraBundleException gbe) {
				BundleStatus status = getStatusFromLoc(gbe.getBundleLocation());
				status.setSummary(gbe.getMessage());
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

	private void addNewStatusNoFire(GhidraBundle gb) {
		BundleStatus status =
			new BundleStatus(gb.getPath(), gb.isEnabled(), gb.isSystemBundle(), gb.getBundleLoc());
		if (statuses.contains(status)) {
			throw new RuntimeException(
				"Bundle status manager already contains " + gb.getPath().toString());
		}
		status.setActive(gb.isActive());
		loc2status.put(status.getBundleLoc(), status);
		statuses.add(status);
	}

	/**
	 *  add new status and fire a table update
	 */
	private void addNewStatus(GhidraBundle gb) {
		int index = statuses.size();
		addNewStatusNoFire(gb);
		fireTableRowsInserted(index, index);
	}

	private int removeStatusNoFire(BundleStatus status) {
		if (!status.isReadOnly()) {
			int i = statuses.indexOf(status);
			statuses.remove(i);
			loc2status.remove(status.getBundleLoc());
			return i;
		}
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

	/** 
	 * (re)compute cached mapping from bundleloc to bundlepath
	 */
	private void computeCache() {
		loc2status.clear();
		for (BundleStatus status : statuses) {
			loc2status.put(status.getBundleLoc(), status);
		}
	}

	/**
	 * This is for testing only!  during normal execution, statuses are only added through BundleHostListener bundle(s) added events.
	 * 
	 * each path is marked editable and non-readonly
	 * 
	 * @param paths the statuses to use
	 */
	public void setPathsForTesting(List<ResourceFile> paths) {
		this.statuses = paths.stream().map(f -> new BundleStatus(f, true, false, null)).collect(
			Collectors.toList());
		computeCache();
		fireTableDataChanged();
	}

}
