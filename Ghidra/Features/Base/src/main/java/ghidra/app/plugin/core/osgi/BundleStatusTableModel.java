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
			return status.pathExists() && status.isEnabled();
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

	private BundleHost bundleHost;
	private BundleStatusComponentProvider provider;
	private Map<String, BundleStatus> bundleLocToStatusMap = new HashMap<>();
	private BundleHostListener bundleHostListener;

	private ArrayList<BundleStatusChangeRequestListener> bundleStatusListeners = new ArrayList<>();
	private List<BundleStatus> statuses;

	protected class MyBundleHostListener implements BundleHostListener {
		@Override
		public void bundleBuilt(GhidraBundle bundle, String summary) {
			BundleStatus status = getStatus(bundle);
			status.setSummary(summary);
			int row = getRowIndex(status);
			fireTableRowsUpdated(row, row);
		}

		@Override
		public void bundleActivationChange(GhidraBundle bundle, boolean newActivation) {
			BundleStatus status = getStatus(bundle);
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
		public void bundleAdded(GhidraBundle bundle) {
			addNewStatus(bundle);
		}

		@Override
		public void bundlesAdded(Collection<GhidraBundle> bundles) {
			int index = statuses.size();
			for (GhidraBundle bundle : bundles) {
				addNewStatusNoFire(bundle);
			}
			fireTableRowsInserted(index, bundles.size() - 1);
		}

		@Override
		public void bundleRemoved(GhidraBundle bundle) {
			BundleStatus status = getStatus(bundle);
			removeStatus(status);
		}

		@Override
		public void bundlesRemoved(Collection<GhidraBundle> bundles) {
			List<BundleStatus> toRemove = bundles.stream()
				.map(BundleStatusTableModel.this::getStatus)
				.collect(Collectors.toUnmodifiableList());
			removeStatuses(toRemove);
		}

		@Override
		public void bundleEnablementChange(GhidraBundle bundle, boolean newEnablement) {
			BundleStatus status = getStatus(bundle);
			status.setEnabled(newEnablement);
			int row = getRowIndex(status);
			fireTableRowsUpdated(row, row);
		}

		@Override
		public void bundleException(GhidraBundleException exception) {
			BundleStatus status = getStatusFromLoc(exception.getBundleLocation());
			status.setSummary(exception.getMessage());
			int row = getRowIndex(status);
			fireTableRowsUpdated(row, row);
		}
	}

	BundleStatusTableModel(BundleStatusComponentProvider provider, BundleHost bundleHost) {
		super();
		this.provider = provider;
		this.bundleHost = bundleHost;
		statuses = new ArrayList<>();
		for (GhidraBundle bundle : bundleHost.getGhidraBundles()) {
			addNewStatus(bundle);
		}

		bundleHost.addListener(bundleHostListener = new MyBundleHostListener());
	}

	Column getColumn(int i) {
		if (i >= 0 && i < columns.size()) {
			return columns.get(i);
		}
		return badColumn;
	}

	BundleStatus getStatus(GhidraBundle bundle) {
		return getStatusFromLoc(bundle.getBundleLocation());
	}

	BundleStatus getStatusFromLoc(String bundleLoc) {
		BundleStatus status = bundleLocToStatusMap.get(bundleLoc);
		if (status == null) {
			Msg.showError(BundleStatusTableModel.this, provider.getComponent(),
				"bundle status error", "bundle has no status!");
		}
		return status;
	}

	@Override
	public void dispose() {
		super.dispose();
		bundleHost.removeListener(bundleHostListener);
	}

	private void addNewStatusNoFire(GhidraBundle bundle) {
		BundleStatus status = new BundleStatus(bundle.getPath(), bundle.isEnabled(),
			bundle.isSystemBundle(), bundle.getBundleLocation());
		if (statuses.contains(status)) {
			throw new RuntimeException(
				"Bundle status manager already contains " + bundle.getPath().toString());
		}
		status.setActive(bundle.isActive());
		bundleLocToStatusMap.put(status.getBundleLocation(), status);
		statuses.add(status);
	}

	/**
	 *  add new status and fire a table update
	 */
	private void addNewStatus(GhidraBundle bundle) {
		int index = statuses.size();
		addNewStatusNoFire(bundle);
		fireTableRowsInserted(index, index);
	}

	private int removeStatusNoFire(BundleStatus status) {
		if (!status.isReadOnly()) {
			int i = statuses.indexOf(status);
			statuses.remove(i);
			bundleLocToStatusMap.remove(status.getBundleLocation());
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
		List<BundleStatus> toRemove = Arrays.stream(modelRows)
			.mapToObj(statuses::get)
			.collect(Collectors.toUnmodifiableList());
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
		// anything that's clicked on should become selected!
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

	void setModelData(List<BundleStatus> statuses) {
		this.statuses = statuses;
		computeCache();
		fireTableDataChanged();
	}

	/**
	 * Add a change request listener.
	 * 
	 * When the user requests a change to the status of a bundle, each listener is called.
	 * 
	 * @param listener the listener to add
	 */
	public void addListener(BundleStatusChangeRequestListener listener) {
		synchronized (bundleStatusListeners) {
			if (!bundleStatusListeners.contains(listener)) {
				bundleStatusListeners.add(listener);
			}
		}
	}

	/**
	 * Remove change request listener.
	 * 
	 * @param listener the listener to remove
	 */
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

	/**
	 * return the row objects corresponding an array of model row indices.  
	 * 
	 * @param modelRowIndices row indices
	 * @return status objects
	 */
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
		bundleLocToStatusMap.clear();
		for (BundleStatus status : statuses) {
			bundleLocToStatusMap.put(status.getBundleLocation(), status);
		}
	}

}
