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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.ArrayList;
import java.util.Set;

import javax.swing.*;
import javax.swing.table.TableColumn;

import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.table.*;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

/**
 * Container for the {@link GTable} that displays ghidra extensions.
 */
public class ExtensionTablePanel extends JPanel {

	private GTableFilterPanel<ExtensionDetails> tableFilterPanel;
	private ExtensionTableModel tableModel;
	private GTable table;

	/**
	 * Constructor; builds the panel and sets table attributes.
	 * 
	 * @param tool the tool showing the extension dialog
	 */
	public ExtensionTablePanel(PluginTool tool) {

		super(new BorderLayout());

		tableModel = new ExtensionTableModel(tool);
		tableModel.setTableSortState(
			TableSortState.createDefaultSortState(ExtensionTableModel.NAME_COL));
		table = new GTable(tableModel);
		table.setPreferredScrollableViewportSize(new Dimension(500, 300));
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		JScrollPane sp = new JScrollPane(table);
		sp.getViewport().setBackground(table.getBackground());
		add(sp, BorderLayout.CENTER);

		tableFilterPanel = new GTableFilterPanel<>(table, tableModel);
		add(tableFilterPanel, BorderLayout.SOUTH);

		HelpService help = Help.getHelpService();
		help.registerHelp(table, new HelpLocation(GenericHelpTopics.FRONT_END, "Extensions"));

		// Restrict the checkbox col to only be 25 pixels wide - the default size is
		// way too large. This is annoying but our table column classes don't have a nice
		// way to restrict column width.
		TableColumn col = table.getColumnModel().getColumn(ExtensionTableModel.INSTALLED_COL);
		col.setMaxWidth(25);

		// Finally, load the table with some data.
		refreshTable();
	}

	public void dispose() {
		tableFilterPanel.dispose();
		table.dispose();
	}

	public ExtensionTableModel getTableModel() {
		return tableModel;
	}

	public GTable getTable() {
		return table;
	}

	public ExtensionDetails getSelectedItem() {
		return tableFilterPanel.getSelectedItem();
	}

	/**
	 * Reloads the table with current extensions.
	 */
	public void refreshTable() {
		tableModel.refreshTable();
	}

	/**
	 * Returns the filter panel.
	 * 
	 * @return the filter panel
	 */
	public GTableFilterPanel<ExtensionDetails> getFilterPanel() {
		return tableFilterPanel;
	}

	/**
	 * Replaces the contents of the table with the given list of extensions.
	 * 
	 * @param extensions the new model data
	 */
	public void setExtensions(Set<ExtensionDetails> extensions) {
		tableModel.setModelData(new ArrayList<>(extensions));
	}
}
