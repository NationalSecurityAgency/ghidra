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
package ghidra.app.plugin.core.reloc;

import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.*;

import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.util.HelpLocation;
import ghidra.util.table.*;

class RelocationProvider extends ComponentProviderAdapter {
	private GhidraTable table;
	private RelocationTableModel tableModel;
	private RelocationTablePlugin plugin;
	private JPanel mainPanel;
	private Program currentProgram;
	private GhidraTableFilterPanel<Relocation> tableFilterPanel;
	private GhidraThreadedTablePanel threadedPanel;

	RelocationProvider(RelocationTablePlugin plugin) {
		super(plugin.getTool(), "Relocation Table", plugin.getName());
		this.plugin = plugin;
		mainPanel = buildMainPanel();
		setHelpLocation(new HelpLocation(plugin.getName(), "Relocation_Table"));
		addToTool();
	}

	/**
	 * @see ghidra.framework.plugintool.ComponentProviderAdapter#getComponent()
	 */
	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public void componentShown() {
		tableModel.setProgram(currentProgram);
	}

	@Override
	public void componentHidden() {
		tableModel.setProgram(null);
	}

	/**
	 * Build the main panel for this component.
	 */
	private JPanel buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());

		ServiceProvider serviceProvider = plugin.getTool();
		tableModel = new RelocationTableModel(serviceProvider, currentProgram, null);
		tableModel.addTableModelListener(e -> {
			int rowCount = tableModel.getRowCount();
			setSubTitle(rowCount + " rows");
		});

		threadedPanel = new GhidraThreadedTablePanel<>(tableModel);
		table = threadedPanel.getTable();

		GoToService goToService = serviceProvider.getService(GoToService.class);
		table.installNavigation(goToService, goToService.getDefaultNavigatable());

		table.setPreferredScrollableViewportSize(new Dimension(300, 200));
		table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_NEXT_COLUMN);

		ToolTipManager.sharedInstance().registerComponent(table);

		panel.add(threadedPanel, BorderLayout.CENTER);

		tableFilterPanel = new GhidraTableFilterPanel<>(table, tableModel);
		panel.add(tableFilterPanel, BorderLayout.SOUTH);

		return panel;
	}

	void setProgram(Program program) {
		currentProgram = program;
		if (isVisible()) {
			tableModel.setProgram(currentProgram);
		}
	}

	GhidraTable getTable() {
		return table;
	}

	void dispose() {
		setProgram(null);
		removeFromTool();
		threadedPanel.dispose();
		tableFilterPanel.dispose();

	}
}
