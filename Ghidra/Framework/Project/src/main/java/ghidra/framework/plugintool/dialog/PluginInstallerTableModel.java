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

import java.util.*;
import java.util.stream.Collectors;

import javax.swing.Icon;
import javax.swing.JComponent;

import docking.widgets.OptionDialog;
import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginDescription;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HTMLUtilities;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import resources.Icons;
import resources.ResourceManager;

/**
 * Table model for the {@link PluginInstallerDialog} dialog. This defines the table columns and
 * their values.
 */
class PluginInstallerTableModel
		extends ThreadedTableModel<PluginDescription, List<PluginDescription>> {

	final static int INSTALLED_COL = 0;
	final static int STATUS_COL = 1;
	final static int NAME_COL = 2;

	public static final Icon EXPERIMENTAL_ICON = ResourceManager.loadImage("images/warning.png");
	public static final Icon DEV_ICON = Icons.STRONG_WARNING_ICON;

	private static Map<PluginStatus, Icon> statusIconMap = new HashMap<>();

	static {
		statusIconMap.put(PluginStatus.UNSTABLE, DEV_ICON);
		statusIconMap.put(PluginStatus.STABLE, EXPERIMENTAL_ICON);
	}

	private PluginConfigurationModel model;
	private List<PluginDescription> pluginDescriptions;
	private JComponent parentComponent;

	/**
	 * Constructs a new data model.
	 * 
	 * @param tool the current tool
	 * @param parentComponent the ui component that should be forced to refresh if a plugin's
	 * state changes.
	 * @param pluginDescriptions the list of plugin descriptions to display
	 * @param model the main plugin configuration model
	 */
	protected PluginInstallerTableModel(PluginTool tool, JComponent parentComponent,
			List<PluginDescription> pluginDescriptions, PluginConfigurationModel model) {
		super("Plugins", tool);

		// TODO: Plugin state changes should probably be broadcast as an event, but
		// for now we are manually causing a repaint of the table component when
		// a plugin is added or removed.
		this.parentComponent = parentComponent;

		this.model = model;
		this.pluginDescriptions = pluginDescriptions;
	}

	@Override
	protected TableColumnDescriptor<PluginDescription> createTableColumnDescriptor() {

		TableColumnDescriptor<PluginDescription> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new PluginInstalledColumn(), -1, false);
		descriptor.addVisibleColumn(new PluginStatusColumn());
		descriptor.addVisibleColumn(new PluginNameColumn(), 1, true);
		descriptor.addVisibleColumn(new PluginDescriptionColumn());
		descriptor.addVisibleColumn(new PluginCategoryColumn());

		return descriptor;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return (columnIndex == INSTALLED_COL);
	}

	@Override
	public int getPrimarySortColumnIndex() {
		return NAME_COL;
	}

	@Override
	public List<PluginDescription> getDataSource() {
		return pluginDescriptions;
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

		PluginDescription targetPluginDescription = getRowObject(rowIndex);
		boolean install = ((Boolean) aValue).booleanValue();
		if (install) {
			addPlugin(targetPluginDescription);
		}
		else {
			List<PluginDescription> pluginsThatUseTarget =
				model.getDependencies(targetPluginDescription);
			String dependenciesToUnloadHtmlList =
				pluginsThatUseTarget.stream().map(PluginDescription::getName).sorted().collect(
					Collectors.joining("<li>", "<ul><li>", "</ul>"));

			if (pluginsThatUseTarget.isEmpty() ||
				OptionDialog.showYesNoDialog(parentComponent, "Confirm plugin removal",
					"<html>Other plugins depend on " +
						HTMLUtilities.escapeHTML(targetPluginDescription.getName()) + "<p><p>" +
						"Removing it will also remove:" + dependenciesToUnloadHtmlList + "<p><p>" +
						"Continue?") == OptionDialog.YES_OPTION) {
				model.removePlugin(targetPluginDescription);
			}

		}

		// Full repaint, as other row data may be changed when adding/removing plugins
		parentComponent.repaint();
	}

	@Override
	protected void doLoad(Accumulator<PluginDescription> accumulator, TaskMonitor monitor)
			throws CancelledException {
		accumulator.addAll(pluginDescriptions);
	}

	private void addPlugin(PluginDescription plugin) {
		if (!plugin.isSlowInstallation()) {
			model.addPlugin(plugin);
			return;
		}

		TaskLauncher.launchModal("Adding Plugin", () -> {
			model.addPlugin(plugin);
		});
	}

	/**
	 * Column for displaying the interactive checkbox, allowing the user to install
	 * or uninstall the plugin.
	 */
	class PluginInstalledColumn extends
			AbstractDynamicTableColumn<PluginDescription, Boolean, List<PluginDescription>> {

		@Override
		public String getColumnName() {
			return "Installation Status";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 25;
		}

		@Override
		public Boolean getValue(PluginDescription rowObject, Settings settings,
				List<PluginDescription> data, ServiceProvider sp) throws IllegalArgumentException {
			return model.isLoaded(rowObject);
		}
	}

	/**
	 * Column for displaying the status of the plugin.
	 */
	class PluginStatusColumn
			extends AbstractDynamicTableColumn<PluginDescription, Icon, List<PluginDescription>> {

		@Override
		public String getColumnName() {
			return "Status";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 25;
		}

		@Override
		public Icon getValue(PluginDescription rowObject, Settings settings,
				List<PluginDescription> data, ServiceProvider sp) throws IllegalArgumentException {
			return statusIconMap.get(rowObject.getStatus());
		}
	}

	/**
	 * Column for displaying the extension name of the plugin.
	 */
	class PluginNameColumn
			extends AbstractDynamicTableColumn<PluginDescription, String, List<PluginDescription>> {

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}

		@Override
		public String getValue(PluginDescription rowObject, Settings settings,
				List<PluginDescription> data, ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getName();
		}
	}

	/**
	 * Column for displaying the plugin description.
	 */
	class PluginDescriptionColumn
			extends AbstractDynamicTableColumn<PluginDescription, String, List<PluginDescription>> {

		@Override
		public String getColumnName() {
			return "Description";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}

		@Override
		public String getValue(PluginDescription rowObject, Settings settings,
				List<PluginDescription> data, ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getShortDescription();
		}
	}

	/**
	 * Column for displaying the plugin category.
	 */
	class PluginCategoryColumn
			extends AbstractDynamicTableColumn<PluginDescription, String, List<PluginDescription>> {

		@Override
		public String getColumnName() {
			return "Category";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}

		@Override
		public String getValue(PluginDescription rowObject, Settings settings,
				List<PluginDescription> data, ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getCategory();
		}
	}
}
