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

import java.awt.Dimension;
import java.util.ArrayList;
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
	private Program trainingSource;
	private Program targetProgram;
	private Address potentialStart;
	private List<SimilarStartRowObject> rows;
	private JSplitPane component;
	private RandomForestRowObject randomForestRow;

	/**
	 * Create a table provider
	 * @param plugin owning plugin
	 * @param trainingSource source of training data
	 * @param targetProgram program being searched
	 * @param potentialStart address of potential start
	 * @param rows closest potential starts
	 * @param randomForestRow model and params
	 */
	public SimilarStartsTableProvider(RandomForestFunctionFinderPlugin plugin,
			Program trainingSource, Program targetProgram, Address potentialStart,
			List<SimilarStartRowObject> rows, RandomForestRowObject randomForestRow) {
		super("Potential Start in " + targetProgram.getName(), plugin.getName(), targetProgram,
			plugin);
		this.trainingSource = trainingSource;
		this.targetProgram = targetProgram;
		this.potentialStart = potentialStart;
		this.rows = rows;
		this.randomForestRow = randomForestRow;
		this.setSubTitle(
			potentialStart.toString() + " compared to closest known starts in training set (from " +
				trainingSource.getName() + ")");
		build();
		setHelpLocation(new HelpLocation(plugin.getName(), "SimilarStartsTable"));
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	/**
	 * Builds the main component for this provider.
	 * <P>
	 * The component is a {@code JSplitPanel} with two {@link GhidraTable}s.  The upper
	 * table consists of a single row containing the potential function start.  The rows
	 * of the lower table contain the function starts in the training source program closest to
	 * the potential function start.  Both tables are navigable; note that the potential
	 * function start may or may not be in training source program. 
	 */
	private void build() {
		SimilarStartsTableModel similarStartsModel =
			new SimilarStartsTableModel(tool, trainingSource, rows, randomForestRow);
		GhidraThreadedTablePanel<SimilarStartRowObject> similarStartsPanel =
			new GhidraThreadedTablePanel<>(similarStartsModel, 1000);
		GhidraTable similarStartsTable = similarStartsPanel.getTable();
		similarStartsPanel.setName(
			targetProgram.getName() + ": Known Starts Similar to " + potentialStart.toString());
		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			similarStartsTable.installNavigation(goToService, goToService.getDefaultNavigatable());
		}
		similarStartsTable.setNavigateOnSelectionEnabled(true);
		similarStartsTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
		similarStartsTable.setPreferredScrollableViewportSize(new Dimension(700, 200));
		similarStartsTable.setToolTipText("Known Starts in " + trainingSource.getName());

		List<SimilarStartRowObject> singleton = new ArrayList<>();
		singleton.add(new SimilarStartRowObject(potentialStart,
			randomForestRow.getRandomForest().getNumModels()));
		SimilarStartsTableModel potentialStartSingletonModel =
			new SimilarStartsTableModel(tool, targetProgram, singleton, randomForestRow);
		GhidraThreadedTablePanel<SimilarStartRowObject> potentialStartPanel =
			new GhidraThreadedTablePanel<>(potentialStartSingletonModel, 1000);
		GhidraTable potentialStartTable = potentialStartPanel.getTable();
		potentialStartTable
				.setToolTipText("Potential Function Start in " + targetProgram.getName());
		if (goToService != null) {
			potentialStartTable.installNavigation(goToService, goToService.getDefaultNavigatable());
		}
		potentialStartTable.setNavigateOnSelectionEnabled(true);
		potentialStartTable.setPreferredScrollableViewportSize(new Dimension(700, 30));
		potentialStartTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
		component =
			new JSplitPane(JSplitPane.VERTICAL_SPLIT, potentialStartPanel, similarStartsPanel);
		component.setResizeWeight(.1);
	}

}
