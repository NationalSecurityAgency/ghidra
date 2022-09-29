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
package ghidra.machinelearning.functionfinding;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.List;

import javax.swing.*;

import ghidra.app.services.GoToService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraThreadedTablePanel;

/**
 * Table provider for a table to display the closest function starts in the training
 * set to a potential function start
 */
public class SimilarStartsTableProvider extends ProgramAssociatedComponentProviderAdapter {
	private Program program;
	private Address potentialStart;
	private List<SimilarStartRowObject> rows;
	private JComponent component;
	private RandomForestRowObject randomForestRow;

	/**
	 * Create a table provider
	 * @param plugin owning plugin
	 * @param program program being search
	 * @param potentialStart address of potential start
	 * @param rows closest potential starts
	 * @param randomForestRow model and params
	 */
	public SimilarStartsTableProvider(RandomForestFunctionFinderPlugin plugin, Program program,
			Address potentialStart, List<SimilarStartRowObject> rows,
			RandomForestRowObject randomForestRow) {
		super(program.getName() + ": Similar Function Starts", plugin.getName(), program, plugin);
		this.program = program;
		this.potentialStart = potentialStart;
		this.rows = rows;
		this.randomForestRow = randomForestRow;
		this.setSubTitle("Function Starts Similar to " + potentialStart.toString());
		build();
		setHelpLocation(new HelpLocation(plugin.getName(), "SimilarStartsTable"));
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	private void build() {
		component = new JPanel(new BorderLayout());
		SimilarStartsTableModel model =
			new SimilarStartsTableModel(tool, program, potentialStart, rows, randomForestRow);
		GhidraThreadedTablePanel<SimilarStartRowObject> similarStartsPanel =
			new GhidraThreadedTablePanel<>(model, 1000);
		GhidraTable similarStartsTable = similarStartsPanel.getTable();
		similarStartsTable.setName(
			program.getName() + ": Known Starts Similar to " + potentialStart.toString());
		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			similarStartsTable.installNavigation(goToService, goToService.getDefaultNavigatable());
		}
		similarStartsTable.setNavigateOnSelectionEnabled(true);
		similarStartsTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
		similarStartsTable.setPreferredScrollableViewportSize(new Dimension(900, 300));
		component.add(similarStartsPanel, BorderLayout.CENTER);
	}

}
