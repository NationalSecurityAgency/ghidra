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

import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;

/**
 * A {@link DockingAction} for showing the most similar function starts in the training
 * set to a possible function start 
 */
public class ShowSimilarStartsAction extends DockingAction {
	private static final String MENU_TEXT = "Show Similar Function Starts";
	private static final String ACTION_NAME = "ShowSimilarStartsAction";
	private static final int NUM_NEIGHBORS = 10;
	private Program trainingSource;
	private Program targetProgram;
	private FunctionStartTableModel model;
	private GhidraTable table;
	private RandomForestRowObject modelAndParams;
	private RandomForestFunctionFinderPlugin plugin;
	private SimilarStartsFinder finder;

	/**
	 * Constructs an action display similar function starts
	 * @param plugin plugin
	 * @param trainingSource source of training data
	 * @param targetProgram program being searched
	 * @param table table
	 * @param model table with action
	 */
	public ShowSimilarStartsAction(RandomForestFunctionFinderPlugin plugin, Program trainingSource,
			Program targetProgram, GhidraTable table, FunctionStartTableModel model) {
		super(ACTION_NAME, plugin.getName());
		this.trainingSource = trainingSource;
		this.targetProgram = targetProgram;
		this.model = model;
		this.table = table;
		this.plugin = plugin;
		this.modelAndParams = model.getRandomForestRowObject();
		init();
		finder = new SimilarStartsFinder(trainingSource, targetProgram, modelAndParams);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return true;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return table.getSelectedRowCount() == 1;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Address potential = model.getAddress(table.getSelectedRow());
		List<SimilarStartRowObject> closeNeighbors =
			finder.getSimilarFunctionStarts(potential, NUM_NEIGHBORS);
		SimilarStartsTableProvider provider = new SimilarStartsTableProvider(plugin, trainingSource,
			targetProgram, potential, closeNeighbors, modelAndParams);
		plugin.addProvider(provider);

	}

	private void init() {
		setPopupMenuData(new MenuData(new String[] { MENU_TEXT }));
		setDescription(
			"Displays the most similar function starts in the training set to the given " +
				"potential start.");
		setHelpLocation(new HelpLocation(plugin.getName(), ACTION_NAME));
	}

}
