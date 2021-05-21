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
package ghidra.app.plugin.core.select.flow;

import java.util.*;

import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import edu.uci.ics.jung.graph.DirectedSparseGraph;
import edu.uci.ics.jung.graph.Graph;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GraphAlgorithms;
import ghidra.graph.jung.JungToGDirectedGraphAdapter;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.block.graph.CodeBlockEdge;
import ghidra.program.model.block.graph.CodeBlockVertex;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * This plugin class contains the structure needed for the user to select code
 * blocks that are only reachable by following the flow from the current program
 * location (they are unreachable from any other starting point).
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Select flows only reachable from current location",
	description = "Allows the user to select code blocks " +
			"by following flows only reachable from the current location within a function"
)
//@formatter:on
public class SelectByScopedFlowPlugin extends ProgramPlugin {
	public SelectByScopedFlowPlugin(PluginTool tool) {
		super(tool, true, true);
		createActions();
	}

	private void createActions() {
		DockingAction action =
			new NavigatableContextAction("Select Forward Scoped Flow", getName()) {
				@Override
				public void actionPerformed(NavigatableActionContext context) {
					FunctionManager functionManager = currentProgram.getFunctionManager();
					Function function =
						functionManager.getFunctionContaining(currentLocation.getAddress());

					if (!isValidFunction(function)) {
						Msg.showWarn(this, null, "Cursor Must Be In a Function",
							"Selecting scoped flow requires the cursor to be " +
								"inside of a function");
						return;
					}

					try {
						ProgramSelection selection = makeForwardScopedSelection(function,
							currentProgram, currentLocation, new TaskMonitorAdapter(true));
						updateStatusText(selection);
						setSelection(selection);
					}
					catch (CancelledException e) {
						Msg.debug(this, "Calculating Forward Scoped Flow cancelled", e);
					}
				}
			};
		action.setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_SELECTION, "Scoped Flow", "Forward Scoped Flow" },
			null, "Select"));
		action.addToWindowWhen(NavigatableActionContext.class);
		action.setDescription("Allows user to select scoped flow from current location.");
		action.setHelpLocation(new HelpLocation("FlowSelection", "Scoped_Flow"));
		tool.addAction(action);

		action = new NavigatableContextAction("Select Reverse Scoped Flow", getName()) {
			@Override
			public void actionPerformed(NavigatableActionContext context) {
				FunctionManager functionManager = currentProgram.getFunctionManager();
				Function function =
					functionManager.getFunctionContaining(currentLocation.getAddress());

				if (!isValidFunction(function)) {
					Msg.showWarn(this, null, "Cursor Must Be In a Function",
						"Selecting scoped flow requires the cursor to be " +
							"inside of a function");
					return;
				}

				try {
					ProgramSelection selection = makeReverseScopedSelection(function,
						currentProgram, currentLocation, new TaskMonitorAdapter(true));
					updateStatusText(selection);
					setSelection(selection);
				}
				catch (CancelledException e) {
					Msg.debug(this, "Calculating Reverse Scoped Flow cancelled", e);
				}
			}
		};
		action.setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_SELECTION, "Scoped Flow", "Reverse Scoped Flow" },
			null, "Select"));
		action.addToWindowWhen(NavigatableActionContext.class);
		action.setDescription("Allows user to select scoped flow to the current location.");
		action.setHelpLocation(new HelpLocation("FlowSelection", "Scoped_Flow"));
		tool.addAction(action);
	}

	private void updateStatusText(ProgramSelection selection) {
		if (selection.isEmpty()) {
			tool.setStatusInfo("Scope Flow Selection: No addresses found in flow");
			return;
		}

		long count = selection.getNumAddresses();
		if (count == 1) {
			tool.setStatusInfo("Scope Flow Selection: Selecting 1 address");
		}
		else {
			tool.setStatusInfo("Scope Flow Selection: Selecting " + count + " addresses");
		}

	}

	private boolean isValidFunction(Function function) {
		if (function == null) {
			return false;
		}

		Listing listing = currentProgram.getListing();
		Address currentAddress = currentLocation.getAddress();
		Instruction instruction = listing.getInstructionAt(currentAddress);
		return instruction != null; // null implies a 'thunk' function
	}

//==================================================================================================
// Algorithm Methods
//==================================================================================================

	private ProgramSelection makeForwardScopedSelection(Function function, Program program,
			ProgramLocation location, TaskMonitor monitor) throws CancelledException {

		return makeSelectionFromVertex(true, function, program, location, monitor);
	}

	private ProgramSelection makeReverseScopedSelection(Function function, Program program,
			ProgramLocation location, TaskMonitor monitor) throws CancelledException {

		return makeSelectionFromVertex(false, function, program, location, monitor);
	}

	private ProgramSelection makeSelectionFromVertex(boolean forwardFlow, Function function,
			Program program, ProgramLocation location, TaskMonitor monitor)
			throws CancelledException {

		Graph<CodeBlockVertex, CodeBlockEdge> graph = createGraph(function, program, monitor);
		CodeBlockVertex from = getVertex(location, graph);

		GDirectedGraph<CodeBlockVertex, CodeBlockEdge> dg = asDirectedGraph(graph);
		Set<CodeBlockVertex> dominated;
		if (forwardFlow) {
			dominated = GraphAlgorithms.findDominance(dg, from, monitor);
		}
		else {
			dominated = GraphAlgorithms.findPostDominance(dg, from, monitor);
		}

		Collection<CodeBlock> blocks = generateCodeBlocksFromVertices(dominated);
		ProgramSelection selection = makeSelectionFromCodeBlocks(blocks, program);
		return selection;
	}

	private CodeBlockVertex getVertex(ProgramLocation location,
			Graph<CodeBlockVertex, CodeBlockEdge> graph) {

		CodeBlockVertex from = null;
		Collection<CodeBlockVertex> vertices = graph.getVertices();
		for (CodeBlockVertex vertex : vertices) {
			CodeBlock codeBlock = vertex.getCodeBlock();
			Address address = location.getAddress();
			if (codeBlock.contains(address)) {
				from = vertex;
				break;
			}
		}

		if (from == null) {
			throw new AssertException("supplied location is not within supplied function");
		}
		return from;
	}

	private GDirectedGraph<CodeBlockVertex, CodeBlockEdge> asDirectedGraph(
			Graph<CodeBlockVertex, CodeBlockEdge> g) {
		return new JungToGDirectedGraphAdapter<>(g);
	}

	private Collection<CodeBlock> generateCodeBlocksFromVertices(
			Collection<CodeBlockVertex> vertices) {
		ArrayList<CodeBlock> result = new ArrayList<>();
		for (CodeBlockVertex vertex : vertices) {
			result.add(vertex.getCodeBlock());
		}
		return result;
	}

	private ProgramSelection makeSelectionFromCodeBlocks(Collection<CodeBlock> blocks,
			Program program) {
		AddressSet set = getAddressForCodeBlocks(blocks, program);
		AddressFactory addressFactory = program.getAddressFactory();
		ProgramSelection selection = new ProgramSelection(addressFactory, set);
		return selection;
	}

	private AddressSet getAddressForCodeBlocks(Collection<CodeBlock> blocks, Program program) {
		AddressSet set = new AddressSet();
		for (CodeBlock codeBlock : blocks) {
			set.add(codeBlock);
		}
		return set;
	}

	private Graph<CodeBlockVertex, CodeBlockEdge> createGraph(Function function, Program program,
			TaskMonitor monitor) throws CancelledException {
		DirectedSparseGraph<CodeBlockVertex, CodeBlockEdge> directedGraph =
			new DirectedSparseGraph<>();
		List<CodeBlockVertex> vertices = createVertices(function, program, monitor);

		addVerticesToGraph(directedGraph, vertices);
		addEdgesToGraph(directedGraph, vertices, monitor);

		return directedGraph;
	}

	private List<CodeBlockVertex> createVertices(Function function, Program program,
			TaskMonitor monitor) throws CancelledException {
		List<CodeBlockVertex> vertices = new ArrayList<>();
		CodeBlockModel blockModel = new BasicBlockModel(program);

		AddressSetView addresses = function.getBody();
		CodeBlockIterator iterator = blockModel.getCodeBlocksContaining(addresses, monitor);
		monitor.initialize(addresses.getNumAddresses());

		for (; iterator.hasNext();) {
			monitor.checkCanceled();
			CodeBlock codeBlock = iterator.next();
			CodeBlockVertex vertex = new CodeBlockVertex(codeBlock);
			vertices.add(vertex);

			long blockAddressCount = codeBlock.getNumAddresses();
			long currentProgress = monitor.getProgress();
			monitor.setProgress(currentProgress + blockAddressCount);
		}

		return vertices;
	}

	private void addVerticesToGraph(
			DirectedSparseGraph<CodeBlockVertex, CodeBlockEdge> directedGraph,
			List<CodeBlockVertex> vertices) {
		for (CodeBlockVertex vertex : vertices) {
			directedGraph.addVertex(vertex);
		}
	}

	private void addEdgesToGraph(Graph<CodeBlockVertex, CodeBlockEdge> graph,
			List<CodeBlockVertex> vertices, TaskMonitor monitor) throws CancelledException {

		Map<CodeBlock, CodeBlockVertex> blockToVertexMap = mapBlocksToVertices(vertices);
		for (CodeBlockVertex startVertex : vertices) {
			monitor.checkCanceled();
			addEdgesForStartVertex(graph, blockToVertexMap, startVertex, monitor);
		}
	}

	private void addEdgesForStartVertex(Graph<CodeBlockVertex, CodeBlockEdge> graph,
			Map<CodeBlock, CodeBlockVertex> blockToVertexMap, CodeBlockVertex start,
			TaskMonitor monitor) throws CancelledException {

		CodeBlock codeBlock = start.getCodeBlock();
		CodeBlockReferenceIterator destinations = codeBlock.getDestinations(monitor);
		for (; destinations.hasNext();) {
			monitor.checkCanceled();
			CodeBlockReference reference = destinations.next();
			CodeBlock destinationBlock = reference.getDestinationBlock();
			CodeBlockVertex end = blockToVertexMap.get(destinationBlock);
			if (end == null) {
				continue; // no vertex means the code block is not in our function
			}

			graph.addEdge(new CodeBlockEdge(start, end), start, end);
		}
	}

	private Map<CodeBlock, CodeBlockVertex> mapBlocksToVertices(List<CodeBlockVertex> vertices) {
		Map<CodeBlock, CodeBlockVertex> blockToVertexMap = new HashMap<>();
		for (CodeBlockVertex vertex : vertices) {
			blockToVertexMap.put(vertex.getCodeBlock(), vertex);
		}
		return blockToVertexMap;
	}
}
