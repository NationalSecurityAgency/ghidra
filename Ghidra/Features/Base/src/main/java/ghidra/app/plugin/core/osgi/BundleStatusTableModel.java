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

import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.event.TableModelEvent;

import org.osgi.framework.Bundle;

import docking.widgets.table.*;
import generic.jar.ResourceFile;
import generic.util.Path;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.*;
import ghidra.util.table.column.*;

/**
 * Model for {@link BundleStatus} objects. 
 */
public class BundleStatusTableModel
		extends GDynamicColumnTableModel<BundleStatus, List<BundleStatus>> {
	private static final Color COLOR_BUNDLE_ERROR = Color.RED;
	private static final Color COLOR_BUNDLE_DISABLED = Color.DARK_GRAY;
	private static final Color COLOR_BUNDLE_BUSY = Color.GRAY;
	private static final Color COLOR_BUNDLE_INACTIVE = Color.BLACK;
	private static final Color COLOR_BUNDLE_ACTIVE = new Color(0.0f, .6f, 0.0f); // a dark green

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

		// sort by path
		setDefaultTableSortState(TableSortState.createDefaultSortState(1, true));
	}

	private BundleStatus getStatus(GhidraBundle bundle) {
		return getStatusFromLoc(bundle.getLocationIdentifier());
	}

	private BundleStatus getStatusFromLoc(String bundleLoc) {
		return bundleLocToStatusMap.get(bundleLoc);
	}

	@Override
	public void dispose() {
		super.dispose();
		bundleHost.removeListener(bundleHostListener);
	}

	@Override
	public void fireTableChanged(TableModelEvent e) {
		Swing.runIfSwingOrRunLater(() -> BundleStatusTableModel.super.fireTableChanged(e));
	}

	// must be called on the swing thread
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
		Swing.runLater(() -> {
			int index = statuses.size();
			addNewStatusNoFire(bundle);
			fireTableRowsInserted(index, index);
		});
	}

	// must be called from the swing thread
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
		Swing.runLater(() -> {
			int rowIndex = removeStatusNoFire(status);
			if (rowIndex >= 0) {
				fireTableRowsDeleted(rowIndex, rowIndex);
			}
		});
	}

	void removeStatuses(List<BundleStatus> toRemove) {
		Swing.runLater(() -> {
			for (BundleStatus status : toRemove) {
				removeStatusNoFire(status);
			}
			fireTableDataChanged();
		});
	}

	/***************************************************/

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		BundleStatus status = statuses.get(rowIndex);
		return ((Column<?>) getColumn(columnIndex)).isEditable(status);
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

	// only used in testing
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
	 * 
	 * <p>only used in testing
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
			if (summary != null) {
				Swing.runLater(() -> {
					BundleStatus status = getStatus(bundle);
					status.setSummary(summary);
					int rowIndex = getRowIndex(status);
					fireTableRowsUpdated(rowIndex, rowIndex);
				});
			}
		}

		@Override
		public void bundleActivationChange(GhidraBundle bundle, boolean newActivation) {
			Swing.runLater(() -> {
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
			});
		}

		@Override
		public void bundleAdded(GhidraBundle bundle) {
			Swing.runLater(() -> {
				addNewStatus(bundle);
			});
		}

		@Override
		public void bundlesAdded(Collection<GhidraBundle> bundles) {
			Swing.runLater(() -> {
				int index = statuses.size();
				for (GhidraBundle bundle : bundles) {
					addNewStatusNoFire(bundle);
				}
				fireTableRowsInserted(index, bundles.size() - 1);
			});
		}

		@Override
		public void bundleRemoved(GhidraBundle bundle) {
			Swing.runLater(() -> {
				BundleStatus status = getStatus(bundle);
				removeStatus(status);
			});
		}

		@Override
		public void bundlesRemoved(Collection<GhidraBundle> bundles) {
			Swing.runLater(() -> {
				List<BundleStatus> toRemove = bundles.stream()
						.map(BundleStatusTableModel.this::getStatus)
						.collect(Collectors.toUnmodifiableList());
				removeStatuses(toRemove);
			});
		}

		@Override
		public void bundleEnablementChange(GhidraBundle bundle, boolean newEnablement) {
			Swing.runLater(() -> {
				BundleStatus status = getStatus(bundle);
				status.setEnabled(newEnablement);
				int rowIndex = getRowIndex(status);
				fireTableRowsUpdated(rowIndex, rowIndex);
			});
		}

		@Override
		public void bundleException(GhidraBundleException exception) {
			Swing.runLater(() -> {
				BundleStatus status = getStatusFromLoc(exception.getBundleLocation());
				if (status != null) {
					status.setSummary(exception.getMessage());
					int rowIndex = getRowIndex(status);
					fireTableRowsUpdated(rowIndex, rowIndex);
				}
			});
		}
	}

	@Override
	public List<BundleStatus> getDataSource() {
		return statuses;
	}

	@Override
	protected TableColumnDescriptor<BundleStatus> createTableColumnDescriptor() {
		TableColumnDescriptor<BundleStatus> columnDescriptor = new TableColumnDescriptor<>();

		columnDescriptor.addVisibleColumn(new EnabledColumn());
		columnDescriptor.addVisibleColumn(new BundleFileColumn());
		columnDescriptor.addVisibleColumn(new BuildSummaryColumn());
		columnDescriptor.addHiddenColumn(new OSGiStatusColumn());
		columnDescriptor.addHiddenColumn(new BundleTypeColumn());

		return columnDescriptor;
	}

	private abstract class Column<COLUMN_TYPE>
			extends AbstractDynamicTableColumn<BundleStatus, COLUMN_TYPE, List<BundleStatus>> {
		final String columnName;

		Column(String columnName) {
			this.columnName = columnName;
		}

		void setValue(BundleStatus status, COLUMN_TYPE aValue) {
			throw new RuntimeException(columnName + " is not editable!");

		}

		boolean isEditable(BundleStatus status) {
			return false;
		}

		@Override
		public String getColumnName() {
			return columnName;
		}

	}

	private class OSGiStatusColumn extends Column<String> {
		OSGiStatusColumn() {
			super("OSGi State");
		}

		@Override
		public String getValue(BundleStatus status, Settings settings, List<BundleStatus> data,
				ServiceProvider serviceProvider0) throws IllegalArgumentException {
			if (!status.isEnabled()) {
				return "(DISABLED)";
			}
			GhidraBundle bundle = bundleHost.getGhidraBundle(status.getFile());
			if (bundle != null) {
				Bundle osgiBundle = bundle.getOSGiBundle();
				if (osgiBundle != null) {
					return OSGiUtils.getStateString(osgiBundle);
				}
				return "(UNINSTALLED)";
			}
			return "(ENABLED)";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	private class BundleTypeColumn extends Column<String> {
		BundleTypeColumn() {
			super("Bundle Type");
		}

		@Override
		public String getValue(BundleStatus status, Settings settings, List<BundleStatus> data,
				ServiceProvider serviceProvider0) throws IllegalArgumentException {
			return status.getType().toString();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 90;
		}

	}

	private class EnabledColumn extends Column<Boolean> {
		EnabledColumn() {
			super("Enabled");
		}

		@Override
		public Boolean getValue(BundleStatus status, Settings settings, List<BundleStatus> data,
				ServiceProvider serviceProvider0) throws IllegalArgumentException {
			return status.isEnabled();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 60;
		}

		@Override
		boolean isEditable(BundleStatus status) {
			return status.fileExists();
		}

		@Override
		void setValue(BundleStatus status, Boolean newValue) {
			fireBundleEnablementChangeRequested(status, newValue);
		}

	}

	private class BundleFileColumn extends Column<ResourceFile> {
		final BundleFileRenderer renderer = new BundleFileRenderer();
		final Comparator<ResourceFile> comparator =
			(a, b) -> Path.toPathString(a).compareTo(Path.toPathString(b));

		BundleFileColumn() {
			super("Path");
		}

		@Override
		public ResourceFile getValue(BundleStatus status, Settings settings,
				List<BundleStatus> data, ServiceProvider serviceProvider0)
				throws IllegalArgumentException {
			return status.getFile();
		}

		@Override
		public GColumnRenderer<ResourceFile> getColumnRenderer() {
			return renderer;
		}

		@Override
		public Comparator<ResourceFile> getComparator() {
			return comparator;
		}

	}

	private class BuildSummaryColumn extends Column<String> {

		BuildSummaryColumn() {
			super("Build Summary");
		}

		@Override
		public String getValue(BundleStatus status, Settings settings, List<BundleStatus> data,
				ServiceProvider serviceProvider0) throws IllegalArgumentException {
			GhidraBundle bundle = bundleHost.getGhidraBundle(status.getFile());
			if (bundle == null) {
				return "no bundle";
			}
			else if (bundle instanceof GhidraPlaceholderBundle) {
				// placeholders will have a summary assigned on construction
				return ((GhidraPlaceholderBundle) bundle).getSummary();
			}
			// other bundles will update their summary on build
			return status.getSummary();
		}

	}

	private class BundleFileRenderer extends AbstractGColumnRenderer<ResourceFile> {

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			BundleStatus status = (BundleStatus) data.getRowObject();
			ResourceFile file = (ResourceFile) data.getValue();
			JLabel label = (JLabel) super.getTableCellRendererComponent(data);
			label.setFont(defaultFont.deriveFont(defaultFont.getStyle() | Font.BOLD));
			label.setText(Path.toPathString(file));
			GhidraBundle bundle = bundleHost.getGhidraBundle(file);
			if (bundle == null || bundle instanceof GhidraPlaceholderBundle || !file.exists()) {
				label.setForeground(COLOR_BUNDLE_ERROR);
			}
			else {
				if (status.isBusy()) {
					label.setForeground(COLOR_BUNDLE_BUSY);
				}
				else if (!status.isEnabled()) {
					label.setForeground(COLOR_BUNDLE_DISABLED);
				}
				else if (status.isActive()) {
					label.setForeground(COLOR_BUNDLE_ACTIVE);
				}
				else {
					label.setForeground(COLOR_BUNDLE_INACTIVE);
				}
			}
			return label;
		}

		@Override
		public String getFilterString(ResourceFile file, Settings settings) {
			return Path.toPathString(file);
		}

	}

}
