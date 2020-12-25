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

import java.awt.*;
import java.util.List;

import javax.swing.*;
import javax.swing.table.TableColumn;

import docking.DialogComponentProvider;
import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.table.*;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.plugintool.PluginConfigurationModel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginDescription;
import ghidra.util.HelpLocation;

/**
 * Dialog that displays plugins in a tabular format, allowing users to install or uninstall them. The
 * plugins that are displayed are defined by the caller.
 *
 */
public class PluginInstallerDialog extends DialogComponentProvider {

	private PluginTool tool;
	private PluginConfigurationModel model;
	private List<PluginDescription> pluginDescriptions;

	private GTableFilterPanel<PluginDescription> tableFilterPanel;
	private PluginDetailsPanel detailsPanel;
	private GTable table;

	/**
	 * Constructs a new provider.
	 * 
	 * @param title the title of the provider
	 * @param tool the current tool
	 * @param pluginDescriptions the list of plugins to display in the dialog
	 */
	public PluginInstallerDialog(String title, PluginTool tool,
			List<PluginDescription> pluginDescriptions) {
		super(title, true, false, true, false);

		this.tool = tool;

		if (model == null) {
			model = new PluginConfigurationModel(tool);
		}

		this.pluginDescriptions = pluginDescriptions;

		addWorkPanel(getWorkPanel());
		addOKButton();
	}

	@Override
	protected void dialogShown() {
		// users often wish to start typing in the filter when the dialog appears
		tableFilterPanel.requestFocus();
	}

	@Override
	protected void okCallback() {
		close();
	}

	@Override
	public void close() {
		super.close();
		tableFilterPanel.dispose();
	}

	/**
	 * Returns the details panel.
	 * <p>
	 * Note: This is primarily for test access
	 * 
	 * @return the details panel
	 */
	PluginDetailsPanel getDetailsPanel() {
		return detailsPanel;
	}

	/**
	 * Returns the filter panel.
	 * <p>
	 * Note: This is primarily for test access
	 * 
	 * @return the filter panel
	 */
	GTableFilterPanel<PluginDescription> getFilterPanel() {
		return tableFilterPanel;
	}

	/**
	 * Returns the plugin configuration model.
	 * <p>
	 * Note: This is primarily for test access
	 * 
	 * @return the plugin configuration model
	 */
	PluginConfigurationModel getModel() {
		return model;
	}

	/**
	 * Returns the main panel for this dialog.
	 */
	private JComponent getWorkPanel() {

		JPanel mainPanel = new JPanel();
		mainPanel.setLayout(new BorderLayout());

		detailsPanel = new PluginDetailsPanel(model);
		JPanel pluginTablePanel = createPluginTablePanel(detailsPanel);

		final JSplitPane splitPane =
			new JSplitPane(JSplitPane.VERTICAL_SPLIT, pluginTablePanel, detailsPanel);
		splitPane.setResizeWeight(.75);
		mainPanel.add(splitPane, BorderLayout.CENTER);

		return mainPanel;
	}

	/**
	 * Creates the panel containing the table of plugins.
	 */
	private JPanel createPluginTablePanel(PluginDetailsPanel pluginDetailsPanel) {

		JPanel pluginTablePanel = new JPanel();
		pluginTablePanel.setLayout(new BorderLayout());

		PluginInstallerTableModel tableModel =
			new PluginInstallerTableModel(tool, getComponent(), pluginDescriptions, model);
		table = new GTable(tableModel);
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		tableFilterPanel = new GTableFilterPanel<>(table, tableModel);

		JScrollPane sp = new JScrollPane(table);
		sp.getViewport().setBackground(table.getBackground());

		pluginTablePanel.add(sp, BorderLayout.CENTER);
		pluginTablePanel.add(tableFilterPanel, BorderLayout.SOUTH);

		// Restrict the size of the first couple columns - the default size is
		// way too large. This is annoying but our table column classes don't have a nice
		// way to restrict column width.
		TableColumn inst_col =
			table.getColumnModel().getColumn(PluginInstallerTableModel.INSTALLED_COL);
		inst_col.setMaxWidth(30);
		TableColumn status_col =
			table.getColumnModel().getColumn(PluginInstallerTableModel.STATUS_COL);
		status_col.setMaxWidth(24);

		tableModel.setTableSortState(
			TableSortState.createDefaultSortState(PluginInstallerTableModel.NAME_COL));
		tableModel.refresh();

		table.getColumnModel()
				.getColumn(PluginInstallerTableModel.NAME_COL)
				.setCellRenderer(
					new NameCellRenderer());
		table.getColumnModel()
				.getColumn(PluginInstallerTableModel.STATUS_COL)
				.setCellRenderer(
					new StatusCellRenderer());

		HelpService help = Help.getHelpService();
		help.registerHelp(table, new HelpLocation(GenericHelpTopics.TOOL, "PluginDialog"));

		table.getSelectionModel().addListSelectionListener(e -> {

			if (e.getValueIsAdjusting()) {
				return;
			}

			int row = table.getSelectedRow();
			if (row < 0 || row > pluginDescriptions.size()) {
				pluginDetailsPanel.setPluginDescription(null);
				return;
			}

			PluginDescription desc = tableFilterPanel.getRowObject(row);
			pluginDetailsPanel.setPluginDescription(desc);
		});

		return pluginTablePanel;
	}

	/**
	 * Renderer for the status column in the table.
	 */
	private class StatusCellRenderer extends GTableCellRenderer {

		public StatusCellRenderer() {
			super();
			setHorizontalAlignment(SwingConstants.CENTER);
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

			Object value = data.getValue();

			renderer.setIcon((value instanceof Icon) ? (Icon) value : null);
			String toolTipText = "";
			if (value == PluginInstallerTableModel.EXPERIMENTAL_ICON) {
				toolTipText = "This plugin is usable, but not fully tested or documented";
			}
			else if (value == PluginInstallerTableModel.DEV_ICON) {
				toolTipText =
					"This plugin is under development and not intended for general use.\n" +
						"It could cause Ghidra to become unstable!";
			}
			renderer.setToolTipText(toolTipText);

			return renderer;
		}
	}

	/**
	 * Renderer for the plugin name column. 
	 */
	private class NameCellRenderer extends GTableCellRenderer {

		NameCellRenderer() {
			defaultFont = getFont();
			boldFont = new Font(defaultFont.getName(), defaultFont.getStyle() | Font.BOLD,
				defaultFont.getSize());
			setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 0));
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

			Object value = data.getValue();
			JTable jtable = data.getTable();
			int row = data.getRowViewIndex();
			boolean isSelected = data.isSelected();

			renderer.setText((String) value);

			PluginDescription desc = tableFilterPanel.getRowObject(row);
			boolean hasDependents = model.hasDependencies(desc);

			if (isSelected) {
				if (hasDependents) {
					renderer.setForeground(Color.pink);
					renderer.setFont(boldFont);
				}
				else {
					renderer.setForeground(jtable.getSelectionForeground());
					renderer.setFont(defaultFont);
				}
			}
			else {
				// set color to red if other plugins depend on this plugin
				if (hasDependents) {
					renderer.setForeground(Color.red);
					renderer.setFont(boldFont);
				}
				else {
					renderer.setForeground(jtable.getForeground());
					renderer.setFont(defaultFont);
				}
			}
			return renderer;
		}
	}
}
