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
package pdb.symbolserver.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.EnumSet;
import java.util.Set;

import javax.swing.*;
import javax.swing.table.TableColumn;

import docking.DockingWindowManager;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GHtmlLabel;
import docking.widgets.label.GLabel;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;
import pdb.PdbPlugin;
import pdb.symbolserver.FindOption;

/**
 * Displays the results of a 'find' operation in a table.
 * Also allows the user to tweak search options.
 */
class SymbolFilePanel extends JPanel {
	interface SearchCallback {
		void searchForPdbs(boolean allowRemote);
	}
	static final String SEARCH_OPTIONS_HELP_ANCHOR = "PDB_Search_Search_Options";
	private SymbolFileTableModel tableModel;
	private GhidraTable table;

	private JPanel tablePanel;
	private JPanel welcomePanel;

	private JButton searchLocalButton;
	private JButton searchAllButton;
	private GCheckBox ignorePdbUid;
	private GCheckBox ignorePdbAge;

	SymbolFilePanel(SearchCallback searchButtonsCallback) {
		super(new BorderLayout());

		build();
		setEnablement(false);
		searchLocalButton.addActionListener(e -> searchButtonsCallback.searchForPdbs(false));
		searchAllButton.addActionListener(e -> searchButtonsCallback.searchForPdbs(true));
	}

	SymbolFileTableModel getTableModel() {
		return tableModel;
	}

	GhidraTable getTable() {
		return table;
	}

	Set<FindOption> getFindOptions() {
		Set<FindOption> findOptions = EnumSet.noneOf(FindOption.class);
		if (ignorePdbAge.isSelected()) {
			findOptions.add(FindOption.ANY_AGE);
		}
		if (ignorePdbUid.isSelected()) {
			findOptions.add(FindOption.ANY_ID);
		}
		return findOptions;
	}

	void setFindOptions(Set<FindOption> findOptions) {
		ignorePdbAge.setSelected(findOptions.contains(FindOption.ANY_AGE));
		ignorePdbUid.setSelected(findOptions.contains(FindOption.ANY_ID));
	}

	void setEnablement(boolean hasSymbolServerService) {
		searchLocalButton.setEnabled(hasSymbolServerService);
		searchAllButton.setEnabled(hasSymbolServerService);

		if (welcomePanel != null && hasSymbolServerService) {
			remove(welcomePanel);
			welcomePanel = null;
			add(tablePanel, BorderLayout.CENTER);
			revalidate();
		}
	}

	SymbolFileRow getSelectedRow() {
		return table.getSelectedRow() != -1
				? tableModel.getRowObject(table.getSelectedRow())
				: null;
	}

	int getSelectedRowIndex() {
		return table.getSelectedRow();
	}

	private void build() {
		setBorder(BorderFactory.createTitledBorder("PDB Search"));
		add(buildButtonPanel(), BorderLayout.NORTH);
		buildTable();	// don't add it yet
		add(buildWelcomePanel(), BorderLayout.CENTER);
	}

	private JPanel buildWelcomePanel() {
		welcomePanel = new JPanel();
		welcomePanel.add(new GHtmlLabel(
			"<html><br><center><font color=red>Configuration must be set first!"));
		welcomePanel.setPreferredSize(tablePanel.getPreferredSize());

		return welcomePanel;
	}

	private JPanel buildTable() {
		this.tableModel = new SymbolFileTableModel();
		this.table = new GhidraTable(tableModel);

		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		TableColumn isMatchColumn = table.getColumnModel().getColumn(0);
		isMatchColumn.setResizable(false);
		isMatchColumn.setPreferredWidth(32);
		isMatchColumn.setMaxWidth(32);
		isMatchColumn.setMinWidth(32);

		// a few extra rows than needed since the table component 
		// will be resized according to the number of warning text
		// lines at the bottom of the dialog
		table.setVisibleRowCount(8);
		table.setPreferredScrollableViewportSize(new Dimension(100, 100));

		tablePanel = new JPanel(new BorderLayout());
		tablePanel.add(new JScrollPane(table), BorderLayout.CENTER);

		return tablePanel;
	}

	private JPanel buildButtonPanel() {
		searchLocalButton = new JButton("Search Local");
		searchLocalButton.setToolTipText("Search local symbol servers only.");
		searchAllButton = new JButton("Search All");
		searchAllButton.setToolTipText("Search local and remote symbol servers.");

		ignorePdbUid = new GCheckBox("Ignore GUID/ID");
		ignorePdbUid.setToolTipText(
			"Find any PDB with same name (local locations only).  Age ignored also.");
		ignorePdbUid.addChangeListener(l -> updateSearchOptionEnablement());

		ignorePdbAge = new GCheckBox("Ignore Age");
		ignorePdbAge.setToolTipText("Find PDB with any age value (local locations only).");

		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));

		panel.add(new GLabel("Search Options:"));
		panel.add(Box.createHorizontalStrut(10));
		panel.add(ignorePdbAge);
		panel.add(Box.createHorizontalStrut(10));
		panel.add(ignorePdbUid);
		panel.add(Box.createHorizontalGlue());
		panel.add(searchLocalButton);
		panel.add(Box.createHorizontalStrut(10));
		panel.add(searchAllButton);

		DockingWindowManager.getHelpService()
				.registerHelp(panel,
					new HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC, SEARCH_OPTIONS_HELP_ANCHOR));

		return panel;
	}

	private void updateSearchOptionEnablement() {
		ignorePdbAge.setEnabled(!ignorePdbUid.isSelected());
	}
}
