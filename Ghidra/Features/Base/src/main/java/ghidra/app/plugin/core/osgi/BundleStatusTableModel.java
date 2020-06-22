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
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import javax.swing.SwingUtilities;
import javax.swing.event.TableModelEvent;

import docking.widgets.table.*;
import generic.jar.ResourceFile;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

/**
 * Model for {@link BundleStatus} objects. 
 */
public class BundleStatusTableModel
		extends GDynamicColumnTableModel<BundleStatus, List<BundleStatus>> {
	Column<Boolean> enabledColumn;
	Column<Boolean> activeColumn;
	Column<String> typeColumn;
	Column<ResourceFile> pathColumn;
	Column<String> summaryColumn;

	private BundleHost bundleHost;
	private BundleStatusComponentProvider provider;
	private Map<String, BundleStatus> bundleLocToStatusMap = new HashMap<>();
	private BundleHostListener bundleHostListener;

	private List<BundleStatusChangeRequestListener> bundleStatusListeners =
		new CopyOnWriteArrayList<>();
	private List<BundleStatus> statuses;

	BundleStatusTableModel(BundleStatusComponentProvider provider, BundleHost bundleHost) {
		super(provider.getTool());
		this.provider = provider;
		this.bundleHost = bundleHost;
		statuses = new ArrayList<>();
		for (GhidraBundle bundle : bundleHost.getGhidraBundles()) {
			addNewStatus(bundle);
		}

		bundleHostListener = new MyBundleHostListener();
		bundleHost.addListener(bundleHostListener);
	}

	BundleStatus getStatus(GhidraBundle bundle) {
		return getStatusFromLoc(bundle.getLocationIdentifier());
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

	@Override
	public void fireTableChanged(TableModelEvent e) {
		if (SwingUtilities.isEventDispatchThread()) {
			super.fireTableChanged(e);
			return;
		}
		final TableModelEvent e1 = e;
		SwingUtilities.invokeLater(() -> BundleStatusTableModel.super.fireTableChanged(e1));
	}

	private void addNewStatusNoFire(GhidraBundle bundle) {
		BundleStatus status = new BundleStatus(bundle.getFile(), bundle.isEnabled(),
			bundle.isSystemBundle(), bundle.getLocationIdentifier());
		if (statuses.contains(status)) {
			throw new RuntimeException(
				"Bundle status manager already contains " + bundle.getFile().toString());
		}
		status.setActive(bundle.isActive());
		bundleLocToStatusMap.put(status.getLocationIdentifier(), status);
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
			int statusIndex = statuses.indexOf(status);
			statuses.remove(statusIndex);
			bundleLocToStatusMap.remove(status.getLocationIdentifier());
			return statusIndex;
		}
		return -1;
	}

	void removeStatus(BundleStatus status) {
		int rowIndex = removeStatusNoFire(status);
		if (rowIndex >= 0) {
			fireTableRowsDeleted(rowIndex, rowIndex);
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
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		BundleStatus status = statuses.get(rowIndex);
		return ((Column<?>) getColumn(columnIndex)).editable(status);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		BundleStatus status = statuses.get(rowIndex);
		Column column = ((Column) getColumn(columnIndex));
		if (column.getColumnClass().isInstance(aValue)) {
			column.setValue(status, aValue);
			// anything that's clicked on should become selected!
			provider.selectModelRow(rowIndex);
		}
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
	 * <p>When the user requests a change to the status of a bundle, each listener is called.
	 * 
	 * @param listener the listener to add
	 */
	public void addListener(BundleStatusChangeRequestListener listener) {
		if (!bundleStatusListeners.contains(listener)) {
			bundleStatusListeners.add(listener);
		}
	}

	/**
	 * Remove change request listener.
	 * 
	 * @param listener the listener to remove
	 */
	public void removeListener(BundleStatusChangeRequestListener listener) {
		bundleStatusListeners.remove(listener);
	}

	void fireBundleEnablementChangeRequested(BundleStatus status, boolean newValue) {
		for (BundleStatusChangeRequestListener listener : bundleStatusListeners) {
			listener.bundleEnablementChangeRequest(status, newValue);
		}
	}

	void fireBundleActivationChangeRequested(BundleStatus status, boolean newValue) {
		for (BundleStatusChangeRequestListener listener : bundleStatusListeners) {
			listener.bundleActivationChangeRequest(status, newValue);
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
		// notify accesses listeners, must be done on swing thread
		SystemUtilities.assertThisIsTheSwingThread("Must be called on the Swing thread");

		if (sortingContext.isUnsorted()) {
			// this is the 'no sort' state
			sortCompleted(sortingContext);
			notifyModelSorted(false);
			return;
		}

		hasEverSorted = true; // signal that we have sorted at least one time

		// wrap the assigned comparator to detect if the order changes

		AtomicBoolean changed = new AtomicBoolean(false);
		Comparator<BundleStatus> wrapper = new Comparator<BundleStatus>() {
			Comparator<BundleStatus> comparator = sortingContext.getComparator();

			@Override
			public int compare(BundleStatus o1, BundleStatus o2) {
				int result = comparator.compare(o1, o2);
				if (result < 0) {
					changed.set(true);
				}
				return result;
			}
		};
		Collections.sort(data, wrapper);
		sortCompleted(sortingContext);
		if (changed.get()) {
			notifyModelSorted(false);
		}
	}

	/** 
	 * (re)compute cached mapping from bundleloc to bundlepath
	 */
	private void computeCache() {
		bundleLocToStatusMap.clear();
		for (BundleStatus status : statuses) {
			bundleLocToStatusMap.put(status.getLocationIdentifier(), status);
		}
	}

	/**
	 * when bundles are added or removed, update the table.
	 * when bundles change enablement or activation, update rows.
	 */
	protected class MyBundleHostListener implements BundleHostListener {
		@Override
		public void bundleBuilt(GhidraBundle bundle, String summary) {
			BundleStatus status = getStatus(bundle);
			status.setSummary(summary);
			int rowIndex = getRowIndex(status);
			fireTableRowsUpdated(rowIndex, rowIndex);
		}

		@Override
		public void bundleActivationChange(GhidraBundle bundle, boolean newActivation) {
			BundleStatus status = getStatus(bundle);
			int rowIndex = getRowIndex(status);
			status.setBusy(false);
			if (newActivation) {
				status.setActive(true);
			}
			else {
				status.setActive(false);
			}
			fireTableRowsUpdated(rowIndex, rowIndex);
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
			int rowIndex = getRowIndex(status);
			fireTableRowsUpdated(rowIndex, rowIndex);
		}

		@Override
		public void bundleException(GhidraBundleException exception) {
			BundleStatus status = getStatusFromLoc(exception.getBundleLocation());
			status.setSummary(exception.getMessage());
			int rowIndex = getRowIndex(status);
			fireTableRowsUpdated(rowIndex, rowIndex);
		}
	}

	@Override
	public List<BundleStatus> getDataSource() {
		return statuses;
	}

	@Override
	protected TableColumnDescriptor<BundleStatus> createTableColumnDescriptor() {
		TableColumnDescriptor<BundleStatus> columnDescriptor = new TableColumnDescriptor<>();
		enabledColumn = new Column<>("Enabled") {
			@Override
			boolean editable(BundleStatus status) {
				return status.fileExists();
			}

			@Override
			Boolean getValue(BundleStatus status) {
				return status.isEnabled();
			}

			@Override
			void setValue(BundleStatus status, Boolean newValue) {
				fireBundleEnablementChangeRequested(status, newValue);
			}
		};
		columnDescriptor.addVisibleColumn(enabledColumn);

		activeColumn = new Column<>("Active") {
			@Override
			boolean editable(BundleStatus status) {
				return status.fileExists() && status.isEnabled();
			}

			@Override
			public Boolean getValue(BundleStatus status) {
				return status.isActive();
			}

			@Override
			void setValue(BundleStatus status, Boolean newValue) {
				fireBundleActivationChangeRequested(status, newValue);
			}

		};
		columnDescriptor.addHiddenColumn(activeColumn);

		typeColumn = new Column<>("Type") {
			public String getValue(BundleStatus status) {
				return status.getType().toString();
			}

		};
		columnDescriptor.addVisibleColumn(typeColumn);

		pathColumn = new Column<>("Path") {
			public ResourceFile getValue(BundleStatus status) {
				return status.getFile();
			}
		};
		columnDescriptor.addVisibleColumn(pathColumn);

		summaryColumn = new Column<>("Summary") {
			public String getValue(BundleStatus status) {
				return status.getSummary();
			}
		};
		columnDescriptor.addVisibleColumn(summaryColumn);

		return columnDescriptor;
	}

	abstract class Column<ROW_TYPE>
			extends AbstractDynamicTableColumn<BundleStatus, ROW_TYPE, List<BundleStatus>> {
		final String name;

		Column(String name) {
			super();
			this.name = name;
		}

		boolean editable(BundleStatus status) {
			return false;
		}

		abstract ROW_TYPE getValue(BundleStatus status);

		@Override
		public ROW_TYPE getValue(BundleStatus rowObject, Settings settings, List<BundleStatus> data,
				ServiceProvider serviceProvider0) throws IllegalArgumentException {
			return getValue(rowObject);
		}

		void setValue(BundleStatus status, ROW_TYPE aValue) {
			throw new RuntimeException(name + " is not editable!");
		}

		@Override
		public String getColumnName() {
			return name;
		}

		int getModelIndex() {
			return getColumnIndex(this);
		}

	}

}
