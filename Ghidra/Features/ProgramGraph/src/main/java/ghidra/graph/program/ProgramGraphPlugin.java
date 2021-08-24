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
package ghidra.graph.program;

import java.util.ArrayList;
import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.graph.GraphDisplayBrokerListener;
import ghidra.app.services.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.graph.*;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.service.graph.GraphDisplayProvider;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskLauncher;

/**
 * Plugin for generating program graphs. It uses the GraphServiceBroker to consume/display
 * the graphs that it generates. This plugin generates several different types of program graphs.
 * Both the "block flow" and "code flow" actions will generate a graph of basic block flows. The only
 * difference is that the "code flow" action generates a graph that
 * displays the assembly for for each basic block, whereas the "block flow" action generates a graph
 * that displays the symbol or address at the start of the basic block.  This plugin also
 * generates call graphs, using either the default subroutine model or one that the user chooses.
 */

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.GRAPH,
	shortDescription = "Program graph generator",
	description = "This plugin provides actions for creating and managing program graphs"
			+ " (block graphs and call graphs)."
			+ "Once a graph is created, it uses the currenly selected graph output to display "
			+ "or export the graph.  The plugin "
			+ "also provides event handling to facilitate interaction between "
			+ "the graph and the tool.",
	servicesRequired = { GoToService.class, BlockModelService.class, GraphDisplayBroker.class },
	eventsProduced = { ProgramLocationPluginEvent.class, ProgramSelectionPluginEvent.class }
)
//@formatter:on
public class ProgramGraphPlugin extends ProgramPlugin
		implements OptionsChangeListener, BlockModelServiceListener, GraphDisplayBrokerListener {

	private static final String PLUGIN_NAME = "Program Graph";

	private static final String OPTIONS_PREFIX = PLUGIN_NAME + Options.DELIMITER;
	private static final String MAX_CODE_LINES_DISPLAYED =
		OPTIONS_PREFIX + "Max Code Lines Displayed";
	private static final String REUSE_GRAPH = OPTIONS_PREFIX + "Reuse Graph";
	private static final String GRAPH_ENTRY_POINT_NEXUS =
		OPTIONS_PREFIX + "Graph Entry Point Nexus";
	private static final String FORCE_LOCATION_DISPLAY_OPTION =
		OPTIONS_PREFIX + "Force Location Visible on Graph";
	private static final String MAX_DEPTH_OPTION = OPTIONS_PREFIX + "Max Reference Depth";
	public static final String MENU_GRAPH = ToolConstants.MENU_GRAPH;

	private BlockModelService blockModelService;

	private List<DockingAction> subUsingGraphActions = new ArrayList<>();
	private ToggleDockingAction reuseGraphAction;
	private ToggleDockingAction appendGraphAction;

	private boolean reuseGraph = false;
	private boolean appendToGraph = false;

	private boolean graphEntryPointNexus = false;
	private int codeLimitPerBlock = 10;
	private int dataMaxDepth = 1;

	private ToggleDockingAction forceLocationVisibleAction;

	private GraphDisplayBroker broker;

	private GraphDisplayProvider defaultGraphService;

	public ProgramGraphPlugin(PluginTool tool) {
		super(tool, true, true);
		intializeOptions();
		registerProgramFlowGraphDisplayOptionsWithTool();
	}

	private void registerProgramFlowGraphDisplayOptionsWithTool() {
		ProgramGraphDisplayOptions displayOptions =
			new ProgramGraphDisplayOptions(new BlockFlowGraphType(), null);

		// this will register Program Flow Graph Type options with the tool
		HelpLocation help = new HelpLocation(getName(), "Program Graphs Display Options");
		displayOptions.registerOptions(tool.getOptions("Graph"), help);
	}

	private void intializeOptions() {
		HelpLocation help = new HelpLocation(getName(), "Graph_Option");
		ToolOptions options = tool.getOptions(ToolConstants.GRAPH_OPTIONS);

		options.registerOption(MAX_CODE_LINES_DISPLAYED, codeLimitPerBlock, help,
			"Specifies the maximum number of instructions to display in each graph " +
				"node in a Code Flow Graph.");

		options.registerOption(REUSE_GRAPH, false, help,
			"Determines whether the graph will reuse the active graph window when displaying " +
				"graphs.");

		options.registerOption(GRAPH_ENTRY_POINT_NEXUS, false, help,
			"Add a dummy node at the root of the graph and adds dummy edges to each node that " +
				"has no incoming edges.");

		options.registerOption(FORCE_LOCATION_DISPLAY_OPTION, false, help,
			"Specifies whether or not graph displays should force the visible graph to pan " +
				"and/or scale to ensure that focused locations are visible.");
		options.registerOption(MAX_DEPTH_OPTION, 1, help,
			"Specifies max depth of data references to graph (0 for no limit)");

		setOptions(options);
		options.addOptionsChangeListener(this);
		options.setOptionsHelpLocation(new HelpLocation(getName(), "Graph_Option"));

	}

	@Override
	protected void init() {
		broker = tool.getService(GraphDisplayBroker.class);
		broker.addGraphDisplayBrokerListener(this);
		defaultGraphService = broker.getDefaultGraphDisplayProvider();

		blockModelService = tool.getService(BlockModelService.class);
		blockModelService.addListener(this);

		createActions();
	}

	@Override
	public void dispose() {
		super.dispose();
		if (blockModelService != null) {
			blockModelService.removeListener(this);
			blockModelService = null;
		}
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		setOptions(options);
	}

	private void setOptions(Options options) {
		codeLimitPerBlock = options.getInt(MAX_CODE_LINES_DISPLAYED, codeLimitPerBlock);
		graphEntryPointNexus = options.getBoolean(GRAPH_ENTRY_POINT_NEXUS, false);
		reuseGraph = options.getBoolean(REUSE_GRAPH, false);
		if (reuseGraphAction != null) {
			reuseGraphAction.setSelected(reuseGraph);
		}
		dataMaxDepth = options.getInt(MAX_DEPTH_OPTION, dataMaxDepth);
		// Note: we don't care about the FORCE_LOCATION_DISPLAY_OPTION. We register it, but its
		// the actually the various GraphDisplays the make use of it.
	}

	private void createActions() {

		new ActionBuilder("Graph Block Flow", getName())
				.menuPath(MENU_GRAPH, "&Block Flow")
				.menuGroup(MENU_GRAPH, "A")
				.onAction(c -> graphBlockFlow())
				.enabledWhen(this::canGraph)
				.buildAndInstall(tool);

		new ActionBuilder("Graph Code Flow", getName())
				.menuPath(MENU_GRAPH, "C&ode Flow")
				.menuGroup(MENU_GRAPH, "B")
				.onAction(c -> graphCodeFlow())
				.enabledWhen(this::canGraph)
				.buildAndInstall(tool);

		new ActionBuilder("Graph Calls Using Default Model", getName())
				.menuPath(MENU_GRAPH, "&Calls")
				.menuGroup(MENU_GRAPH, "C")
				.onAction(c -> graphSubroutines())
				.enabledWhen(this::canGraph)
				.buildAndInstall(tool);

		tool.setMenuGroup(new String[] { MENU_GRAPH, "Data" }, "Graph", "Data");
		HelpLocation helpLoc = new HelpLocation(getName(), "Data_Reference_Graph");

		new ActionBuilder("Graph To/From Data References", getName())
				.menuPath(MENU_GRAPH, "Data", "To/From &References")
				.menuGroup(MENU_GRAPH, "Data")
				.helpLocation(helpLoc)
				.onAction(c -> graphDataReferences())
				.enabledWhen(this::canGraph)
				.buildAndInstall(tool);

		new ActionBuilder("Graph To Data References", getName())
				.menuPath(MENU_GRAPH, "Data", "&To References")
				.menuGroup(MENU_GRAPH, "Data")
				.helpLocation(helpLoc)
				.onAction(c -> graphToDataReferences())
				.enabledWhen(this::canGraph)
				.buildAndInstall(tool);

		new ActionBuilder("Graph From Data References", getName())
				.menuPath(MENU_GRAPH, "Data", "&From References")
				.menuGroup(MENU_GRAPH, "Data")
				.helpLocation(helpLoc)
				.onAction(c -> graphFromDataReferences())
				.enabledWhen(this::canGraph)
				.buildAndInstall(tool);

		reuseGraphAction =
			new ToggleActionBuilder("Reuse Graph", getName())
					.menuPath(MENU_GRAPH, "Reuse Graph")
					.menuGroup("Graph Options")
					.selected(reuseGraph)
					.onAction(c -> reuseGraph = reuseGraphAction.isSelected())
					.enabledWhen(this::canGraph)
					.buildAndInstall(tool);

		appendGraphAction =
			new ToggleActionBuilder("Append Graph", getName())
					.menuPath(MENU_GRAPH, "Append Graph")
					.menuGroup("Graph Options")
					.selected(false)
					.onAction(c -> updateAppendAndReuseGraph())
					.enabledWhen(this::canGraph)
					.buildAndInstall(tool);

		forceLocationVisibleAction = new ToggleActionBuilder("Show Location in Graph", getName())
				.menuPath(MENU_GRAPH, "Show Location")
				.description("Tell the graph to pan/scale as need to keep location changes visible")
				.menuGroup("Graph Options")
				.onAction(c -> toggleForceLocationVisible())
				.enabledWhen(this::canGraph)
				.buildAndInstall(tool);

		updateSubroutineActions();
	}

	private boolean canGraph(ActionContext context) {
		return currentProgram != null && defaultGraphService != null;
	}

	private void toggleForceLocationVisible() {
		ToolOptions options = tool.getOptions("Graph");
		options.setBoolean(FORCE_LOCATION_DISPLAY_OPTION, forceLocationVisibleAction.isSelected());
	}

	private void updateAppendAndReuseGraph() {
		appendToGraph = appendGraphAction.isSelected();
		if (appendToGraph && !reuseGraph) {
			reuseGraph = true;
			reuseGraphAction.setSelected(true);
		}
	}

	private void updateSubroutineActions() {

		// Remove old actions
		for (DockingAction action : subUsingGraphActions) {
			tool.removeAction(action);
		}

		// Create subroutine graph actions for each subroutine provided by BlockModelService

		String[] subModels =
			blockModelService.getAvailableModelNames(BlockModelService.SUBROUTINE_MODEL);

		if (subModels.length <= 1) { // Not needed if only one subroutine model
			return;
		}

		HelpLocation helpLoc = new HelpLocation(getName(), "Graph_Calls_Using_Model");
		for (String blockModelName : subModels) {
			DockingAction action = buildGraphActionWithModel(blockModelName, helpLoc);
			subUsingGraphActions.add(action);
		}

		tool.setMenuGroup(new String[] { MENU_GRAPH, "Calls Using Model" }, "Graph", "C");
	}

	private DockingAction buildGraphActionWithModel(String blockModelName, HelpLocation helpLoc) {
		return new ActionBuilder("Graph Calls using " + blockModelName, getName())
				.menuPath(MENU_GRAPH, "Calls Using Model", blockModelName)
				.menuGroup(MENU_GRAPH, "C")
				.helpLocation(helpLoc)
				.onAction(c -> graphSubroutinesUsing(blockModelName))
				.enabledWhen(this::canGraph)
				.buildAndInstall(tool);
	}

	private void graphBlockFlow() {
		graph(new BlockFlowGraphType(), blockModelService.getActiveBlockModelName());
	}

	private void graphCodeFlow() {
		graph(new CodeFlowGraphType(), blockModelService.getActiveBlockModelName());
	}

	private void graphSubroutines() {
		graph(new CallGraphType(), blockModelService.getActiveSubroutineModelName());
	}

	private void graphSubroutinesUsing(String modelName) {
		graph(new CallGraphType(), modelName);
	}

	private void graphDataReferences() {
		graphData(DataReferenceGraph.Directions.BOTH_WAYS);
	}

	private void graphToDataReferences() {
		graphData(DataReferenceGraph.Directions.TO_ONLY);
	}

	private void graphFromDataReferences() {
		graphData(DataReferenceGraph.Directions.FROM_ONLY);
	}

	private void graph(ProgramGraphType graphType, String modelName) {
		try {
			CodeBlockModel model =
				blockModelService.getNewModelByName(modelName, currentProgram, true);
			BlockGraphTask task =
				new BlockGraphTask(graphType, graphEntryPointNexus,
				reuseGraph, appendToGraph, tool, currentSelection, currentLocation, model,
				defaultGraphService);
			task.setCodeLimitPerBlock(codeLimitPerBlock);
			new TaskLauncher(task, tool.getToolFrame());
		}
		catch (NotFoundException e) {
			Msg.showError(this, null, "Error That Can't Happen",
				"Can't find a block model from a name that we got from the existing block models!");
		}
	}

	void graphData(DataReferenceGraph.Directions direction) {
		DataReferenceGraphTask task =
			new DataReferenceGraphTask(reuseGraph, appendToGraph, tool, currentSelection,
				currentLocation, defaultGraphService, dataMaxDepth, codeLimitPerBlock, direction);
		new TaskLauncher(task, tool.getToolFrame());
	}

	String getProgramName() {
		return currentProgram != null ? currentProgram.getName() : null;
	}

	@Override
	public void modelAdded(String modeName, int modelType) {
		if (modelType == BlockModelService.SUBROUTINE_MODEL) {
			updateSubroutineActions();
		}
	}

	@Override
	public void modelRemoved(String modeName, int modelType) {
		if (modelType == BlockModelService.SUBROUTINE_MODEL) {
			updateSubroutineActions();
		}
	}

	@Override
	public void providersChanged() {
		defaultGraphService = broker.getDefaultGraphDisplayProvider();
	}

}
