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
package ghidra.framework.project.extensions;

import java.awt.Component;
import java.util.*;

import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModel;
import generic.jar.ResourceFile;
import ghidra.docking.settings.Settings;
import ghidra.framework.Application;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.extensions.ExtensionDetails;
import ghidra.util.extensions.ExtensionUtils;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.task.TaskMonitor;

/**
 * Model for the {@link ExtensionTablePanel}. This defines 5 columns for displaying information in
 * {@link ExtensionDetails} objects:
 * <pre>
 * 		- Installation Status
 * 		- Name
 * 		- Description
 * 		- Version
 * 		- Installation Directory (hidden)
 * 		- Archive File (hidden)
 * </pre>
 * <p>
 * All columns are for display purposes only, except for the <code>installed</code> column, which
 * is a checkbox allowing users to install/uninstall a particular extension.
 *
 */
class ExtensionTableModel extends ThreadedTableModel<ExtensionRowObject, Object> {

	/** We don't care about the ordering of other columns, but the install/uninstall checkbox should be
	 the first one and the name col is our initial sort column. */
	final static int INSTALLED_COL = 0;
	final static int NAME_COL = 1;

	/** This is the data source for the model. Whatever is here will be displayed in the table. */
	private Set<ExtensionRowObject> extensions;
	private Map<String, Boolean> originalInstallStates = new HashMap<>();

	/**
	 * Constructor.
	 *
	 * @param serviceProvider the tool providing the extensions table
	 */
	protected ExtensionTableModel(ServiceProvider serviceProvider) {
		super("Extensions", serviceProvider);
	}

	@Override
	protected TableColumnDescriptor<ExtensionRowObject> createTableColumnDescriptor() {

		TableColumnDescriptor<ExtensionRowObject> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new ExtensionInstalledColumn(), INSTALLED_COL, true);
		descriptor.addVisibleColumn(new ExtensionNameColumn(), NAME_COL, true);
		descriptor.addVisibleColumn(new ExtensionDescriptionColumn());
		descriptor.addVisibleColumn(new ExtensionVersionColumn());
		descriptor.addHiddenColumn(new ExtensionInstallationDirColumn());
		descriptor.addHiddenColumn(new ExtensionArchiveFileColumn());

		return descriptor;
	}

	@Override
	public int getPrimarySortColumnIndex() {
		return NAME_COL;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (Application.inSingleJarMode()) {
			return false;
		}

		// Do not allow GUI removal of extensions manually installed in installation directory or
		// in a repo directory.
		ExtensionDetails extension = getSelectedExtension(rowIndex);
		if (extension.isInstalledInInstallationFolder()) {
			return false;
		}

		return columnIndex == INSTALLED_COL;
	}

	/**
	 * Overridden to handle the case where a user has toggled the installation column
	 * checkbox.
	 */
	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {

		// We only care about the install column here, as it's the only one that is editable.
		if (columnIndex != INSTALLED_COL) {
			return;
		}

		// If the user does not have write permissions on the installation dir, they cannot install.
		List<ResourceFile> dirs = Application.getApplicationLayout().getExtensionInstallationDirs();
		ResourceFile installDir = dirs.get(0);
		if (!installDir.exists() && !installDir.mkdir()) {
			Msg.showError(this, null, "Directory Error",
				"Cannot install/uninstall extensions: Failed to create installation directory.\n" +
					"See the 'Ghidra Extension Notes' section of the Ghidra Installation Guide.");
		}
		if (!installDir.canWrite()) {
			Msg.showError(this, null, "Permissions Error",
				"Cannot install/uninstall extensions: Cannot write to installation directory.\n" +
					"See the 'Ghidra Extension Notes' section of the Ghidra Installation Guide.");
			return;
		}

		boolean install = ((Boolean) aValue).booleanValue();
		ExtensionDetails extension = getSelectedExtension(rowIndex);
		if (!install) {
			if (extension.markForUninstall()) {
				refreshTable();
			}
			return;
		}

		// Restore an existing extension or install an archived extension
		if (extension.isPendingUninstall()) {
			if (extension.clearMarkForUninstall()) {
				refreshTable();
				return;
			}
		}

		// At this point, the extension is not installed, so we cannot simply clear the uninstall
		// state.  This means that the extension has not yet been installed.  The only way to get
		// into this state is by clicking an extension that was discovered in the 'extension 
		// archives folder'		
		if (extension.isFromArchive()) {
			if (ExtensionInstaller.installExtensionFromArchive(extension)) {
				refreshTable();
			}
			return;
		}

		// This is a programming error
		Msg.error(this,
			"Unable install an extension that no longer exists.\n" +
				"Restart Ghidra and try manually installing the extension: '" +
				extension.getName() + "'");
	}

	/**
	 * Returns true if the extension version is valid for this version of Ghidra.
	 *
	 * @param details the extension to check
	 * @return true if extension version is valid for this version of Ghidra
	 */
	private boolean matchesGhidraVersion(ExtensionDetails details) {
		String ghidraVersion = Application.getApplicationVersion();
		String extensionVersion = details.getVersion();
		return ghidraVersion.equals(extensionVersion);
	}

	@Override
	public Object getDataSource() {
		return null;
	}

	@Override
	protected void doLoad(Accumulator<ExtensionRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (extensions != null) {
			accumulator.addAll(extensions);
			return;
		}

		ExtensionUtils.reload();
		Set<ExtensionDetails> archived = ExtensionUtils.getArchiveExtensions();
		Set<ExtensionInstallationInfo> installed = ExtensionInstallationInfo.get();

		extensions = new HashSet<>();

		// don't show archived extensions that have been installed
		for (ExtensionInstallationInfo info : installed) {

			ExtensionDetails e = info.getExtension();
			if (archived.remove(e)) {
				Msg.trace(this,
					"Not showing archived extension that has been installed.  Archive path: " +
						e.getArchivePath()); // useful for debugging
			}

			extensions.add(new ExtensionRowObject(e, info));
		}

		for (ExtensionDetails e : archived) {
			extensions.add(new ExtensionRowObject(e));
		}

		for (ExtensionRowObject ro : extensions) {
			ExtensionDetails e = ro.getExtension();
			String name = e.getName();
			if (originalInstallStates.containsKey(name)) {
				continue; // preserve the original value
			}
			originalInstallStates.put(e.getName(), e.isInstalled());
		}

		accumulator.addAll(extensions);
	}

	/**
	 * Returns true if the model has changed as a result of installing or uninstalling an extension
	 *
	 * @return true if the model has changed as a result of installing or uninstalling an extension
	 */
	public boolean hasModelChanged() {

		for (ExtensionRowObject ro : extensions) {
			ExtensionDetails e = ro.getExtension();
			Boolean wasInstalled = originalInstallStates.get(e.getName());
			if (wasInstalled == null) {
				return false;
			}
			if (e.isInstalled() != wasInstalled) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Replaces the table model data with the given list.
	 *
	 * @param model the list to use as the model
	 */
	public void setModelData(List<ExtensionDetails> model) {

		extensions = new HashSet<>();
		for (ExtensionDetails e : model) {
			extensions.add(new ExtensionRowObject(e));
		}

		reload();
	}

	/**
	 * Gets a new set of extensions and reloads the table.
	 */
	public void refreshTable() {
		extensions = null;
		reload();
	}

	/**
	 * Returns the selected extension.
	 * <p>
	 * Note that this table is single-selection only, so this will only
	 * ever return 1 item.
	 *
	 * @param row the selected row
	 * @return the selected extension, or null if nothing is selected
	 */
	private ExtensionDetails getSelectedExtension(int row) {
		ExtensionRowObject ro = getRowObject(row);
		if (ro != null) {
			return ro.getExtension();
		}
		return null;
	}

	/**
	 * Table column for displaying the extension name.
	 */
	private class ExtensionNameColumn
			extends AbstractDynamicTableColumn<ExtensionRowObject, String, Object> {

		private ExtRenderer renderer = new ExtRenderer();

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 50;
		}

		@Override
		public String getValue(ExtensionRowObject rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getExtension().getName();
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return renderer;
		}
	}

	/**
	 * Table column for displaying the extension description.
	 */
	private class ExtensionDescriptionColumn
			extends AbstractDynamicTableColumn<ExtensionRowObject, String, Object> {

		private ExtRenderer renderer = new ExtRenderer();

		@Override
		public String getColumnName() {
			return "Description";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}

		@Override
		public String getValue(ExtensionRowObject rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getExtension().getDescription();
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return renderer;
		}
	}

	/**
	 * Table column for displaying the extension description.
	 */
	private class ExtensionVersionColumn
			extends AbstractDynamicTableColumn<ExtensionRowObject, String, Object> {

		private ExtRenderer renderer = new ExtRenderer();

		@Override
		public String getColumnName() {
			return "Version";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 50;
		}

		@Override
		public String getValue(ExtensionRowObject rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {

			String version = rowObject.getExtension().getVersion();

			// Check for the default version value. If this is still set, then no version has been
			// established so just display an empty string.
			if (version == null || version.equals("@extversion@")) {
				return "";
			}

			return version;
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return renderer;
		}
	}

	/**
	 * Table column for displaying the extension installation status.
	 */
	private class ExtensionInstalledColumn
			extends AbstractDynamicTableColumn<ExtensionRowObject, Boolean, Object> {

		@Override
		public String getColumnName() {
			return "Installation Status";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 30;
		}

		@Override
		public Boolean getValue(ExtensionRowObject rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getExtension().isInstalled();
		}
	}

	/**
	 * Table column for displaying the extension installation directory.
	 */
	private class ExtensionInstallationDirColumn
			extends AbstractDynamicTableColumn<ExtensionRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Installation Directory";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}

		@Override
		public String getValue(ExtensionRowObject rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getExtension().getInstallPath();
		}
	}

	/**
	 * Table column for displaying the extension archive file.
	 */
	private class ExtensionArchiveFileColumn
			extends AbstractDynamicTableColumn<ExtensionRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Archive File";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}

		@Override
		public String getValue(ExtensionRowObject rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getExtension().getArchivePath();
		}
	}

	private class ExtRenderer extends AbstractGColumnRenderer<String> {

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			Component comp = super.getTableCellRendererComponent(data);

			ExtensionDetails extension = getSelectedExtension(data.getRowViewIndex());
			if (!matchesGhidraVersion(extension)) {
				comp.setForeground(getErrorForegroundColor(data.isSelected()));
			}

			return comp;
		}

		@Override
		public String getFilterString(String t, Settings settings) {
			return t;
		}
	}
}
