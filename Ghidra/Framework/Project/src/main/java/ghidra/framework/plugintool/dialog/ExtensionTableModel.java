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
package ghidra.framework.plugintool.dialog;

import java.awt.Color;
import java.awt.Component;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModel;
import generic.jar.ResourceFile;
import ghidra.docking.settings.Settings;
import ghidra.framework.Application;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * Model for the {@link ExtensionTablePanel}. This defines 5 columns for displaying information in
 * {@link ExtensionDetails} objects:
 * <p>
 * <pre>
 * 		- Installed (checkbox)
 * 		- Name
 * 		- Description
 * 		- Installation directory (hidden)
 * 		- Archive directory (hidden)
 * </pre>
 * <p>
 * All columns are for display purposes only, except for the <code>installed</code> column, which 
 * is a checkbox allowing users to install/uninstall a particular extension. 
 * 
 */
class ExtensionTableModel extends ThreadedTableModel<ExtensionDetails, List<ExtensionDetails>> {

	/** We don't care about the ordering of other columns, but the install/uninstall checkbox should be 
	 the first one and the name col is our initial sort column. */
	final static int INSTALLED_COL = 0;
	final static int NAME_COL = 1;

	/** This is the data source for the model. Whatever is here will be displayed in the table. */
	private List<ExtensionDetails> extensions = new ArrayList<>();

	/** Indicates if the model has changed due to an install or uninstall. */
	private boolean modelChanged = false;

	/**
	 * Constructor.
	 * 
	 * @param serviceProvider the tool providing the extensions table
	 */
	protected ExtensionTableModel(ServiceProvider serviceProvider) {
		super("Extensions", serviceProvider);
	}

	@Override
	protected TableColumnDescriptor<ExtensionDetails> createTableColumnDescriptor() {

		TableColumnDescriptor<ExtensionDetails> descriptor =
			new TableColumnDescriptor<ExtensionDetails>();

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
		if (Application.inSingleJarMode() || SystemUtilities.isInDevelopmentMode()) {
			return false;
		}

		ExtensionDetails extension = getSelectedExtension(rowIndex);
		if (!isValidVersion(extension)) {
			return false;
		}

		// Do not allow GUI uninstallation of extensions manually installed in installation 
		// directory
		if (extension.getInstallPath() != null && FileUtilities.isPathContainedWithin(
			Application.getApplicationLayout().getApplicationInstallationDir().getFile(false),
			new File(extension.getInstallPath()))) {
			return false;
		}

		return (columnIndex == INSTALLED_COL);
	}

	/**
	 * Overridden to handle the case where a user has toggled the installation column
	 * checkbox.
	 */
	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		super.setValueAt(aValue, rowIndex, columnIndex);

		// We only care about the install column here, as it's the only one that
		// is editable. 
		if (columnIndex != INSTALLED_COL) {
			return;
		}

		// If the user does not have write permissions on the installation dir, they cannot 
		// install.
		ResourceFile installDir =
			Application.getApplicationLayout().getExtensionInstallationDirs().get(0);
		if (!installDir.exists() && !installDir.mkdir()) {
			Msg.showError(this, null, "Directory Error",
				"Cannot install/uninstall extensions: Failed to create extension installation directory.\n" +
					"See the \"Ghidra Extension Notes\" section of the Ghidra Installation Guide for more information.");
		}
		if (!installDir.canWrite()) {
			Msg.showError(this, null, "Permissions Error",
				"Cannot install/uninstall extensions: Invalid write permissions on installation directory.\n" +
					"See the \"Ghidra Extension Notes\" section of the Ghidra Installation Guide for more information.");
			return;
		}

		boolean install = ((Boolean) aValue).booleanValue();
		ExtensionDetails extension = getSelectedExtension(rowIndex);

		if (install) {
			if (ExtensionUtils.install(extension, true)) {
				modelChanged = true;
			}
		}
		else {
			if (ExtensionUtils.removeStateFiles(extension)) {
				modelChanged = true;
			}
		}

		refreshTable();
	}

	/**
	 * Returns true if the extension version is valid for this version of Ghidra.
	 *
	 * @param details the extension to check
	 * @return true if extension version is valid for this version of Ghidra
	 */
	private boolean isValidVersion(ExtensionDetails details) {
		String ghidraVersion = Application.getApplicationVersion();
		String extensionVersion = details.getVersion();

		return ghidraVersion.equals(extensionVersion);
	}

	@Override
	public List<ExtensionDetails> getDataSource() {
		return extensions;
	}

	@Override
	protected void doLoad(Accumulator<ExtensionDetails> accumulator, TaskMonitor monitor)
			throws CancelledException {
		accumulator.addAll(extensions);
	}

	/**
	 * Returns true if the model has changed as a result of installing or uninstalling an extension.
	 * 
	 * @return true if the model has changed as a result of installing or uninstalling an extension.
	 */
	public boolean hasModelChanged() {
		return modelChanged;
	}

	/**
	 * Replaces the table model data with the given list.
	 * 
	 * @param model the list to use as the model
	 */
	public void setModelData(List<ExtensionDetails> model) {
		extensions = model;
		reload();
	}

	/**
	 * Gets a new set of extensions and reloads the table.
	 */
	public void refreshTable() {
		try {
			setModelData(new ArrayList<ExtensionDetails>(ExtensionUtils.getExtensions()));
		}
		catch (ExtensionException e) {
			Msg.error(this, "Error loading extensions", e);
		}
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
		return getRowObject(row);
	}

	/**
	 * Table column for displaying the extension name.
	 */
	private class ExtensionNameColumn
			extends AbstractDynamicTableColumn<ExtensionDetails, String, List<ExtensionDetails>> {

		private ExtVersionRenderer renderer = new ExtVersionRenderer();

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 50;
		}

		@Override
		public String getValue(ExtensionDetails rowObject, Settings settings,
				List<ExtensionDetails> data, ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getName();
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
			extends AbstractDynamicTableColumn<ExtensionDetails, String, List<ExtensionDetails>> {

		private ExtVersionRenderer renderer = new ExtVersionRenderer();

		@Override
		public String getColumnName() {
			return "Description";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}

		@Override
		public String getValue(ExtensionDetails rowObject, Settings settings,
				List<ExtensionDetails> data, ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getDescription();
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
			extends AbstractDynamicTableColumn<ExtensionDetails, String, List<ExtensionDetails>> {

		private ExtVersionRenderer renderer = new ExtVersionRenderer();

		@Override
		public String getColumnName() {
			return "Version";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 50;
		}

		@Override
		public String getValue(ExtensionDetails rowObject, Settings settings,
				List<ExtensionDetails> data, ServiceProvider sp) throws IllegalArgumentException {

			String version = rowObject.getVersion();

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
			extends AbstractDynamicTableColumn<ExtensionDetails, Boolean, List<ExtensionDetails>> {

		@Override
		public String getColumnName() {
			return "Installation Status";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 30;
		}

		@Override
		public Boolean getValue(ExtensionDetails rowObject, Settings settings,
				List<ExtensionDetails> data, ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.isInstalled();
		}
	}

	/**
	 * Table column for displaying the extension installation directory.
	 */
	private class ExtensionInstallationDirColumn
			extends AbstractDynamicTableColumn<ExtensionDetails, String, List<ExtensionDetails>> {

		@Override
		public String getColumnName() {
			return "Installation Directory";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}

		@Override
		public String getValue(ExtensionDetails rowObject, Settings settings,
				List<ExtensionDetails> data, ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getInstallPath();
		}
	}

	/**
	 * Table column for displaying the extension archive file.
	 */
	private class ExtensionArchiveFileColumn
			extends AbstractDynamicTableColumn<ExtensionDetails, String, List<ExtensionDetails>> {

		@Override
		public String getColumnName() {
			return "Archive File";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}

		@Override
		public String getValue(ExtensionDetails rowObject, Settings settings,
				List<ExtensionDetails> data, ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getArchivePath();
		}
	}

	private class ExtVersionRenderer extends AbstractGColumnRenderer<String> {

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			Component comp = super.getTableCellRendererComponent(data);

			ExtensionDetails extension = getSelectedExtension(data.getRowViewIndex());
			if (data.isSelected()) {
				comp.setForeground(Color.WHITE);
			}
			else {
				if (isValidVersion(extension) || SystemUtilities.isInDevelopmentMode()) {
					comp.setForeground(Color.BLACK);
				}
				else {
					comp.setForeground(Color.RED);
				}
			}
			return comp;
		}

		@Override
		public String getFilterString(String t, Settings settings) {
			return t;
		}
	}
}
