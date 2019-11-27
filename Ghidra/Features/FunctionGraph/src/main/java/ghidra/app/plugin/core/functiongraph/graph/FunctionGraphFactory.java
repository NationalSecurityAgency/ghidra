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
package ghidra.app.plugin.core.functiongraph.graph;

import static ghidra.app.plugin.core.functiongraph.graph.FGVertexType.*;

import java.util.*;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;

import edu.uci.ics.jung.graph.Graph;
import ghidra.app.plugin.core.functiongraph.graph.layout.*;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.ListingFunctionGraphVertex;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FunctionGraphFactory {

	/**
	 * Clones the given function graph, creating a new graph with cloned versions of each
	 * vertex and edge. 
	 * 
	 * @param data the data of the current graph
	 * @param newController controller for the new graph
	 * @return a new data object containing the new graph 
	 */
	public static FGData createClonedGraph(FGData data, FGController newController) {

		Function function = data.getFunction();
		FunctionGraph originalGraph = data.getFunctionGraph();

		FunctionGraph newGraph = cloneGraph(originalGraph, newController);
		cloneLayout(originalGraph, newGraph);

		return new FGData(function, newGraph);
	}

	private static FunctionGraph cloneGraph(FunctionGraph originalGraph,
			FGController newController) {

		Map<FGVertex, FGVertex> oldToNewCloneMap =
			cloneVertices(originalGraph.getUngroupedVertices(), newController);
		Collection<FGVertex> vertices = oldToNewCloneMap.values();

		Set<FGEdge> originalEdges = originalGraph.getUngroupedEdges();
		Collection<FGEdge> edges =
			cloneEdges(originalGraph, oldToNewCloneMap, originalEdges, newController);

		Program program = newController.getProgram();
		FunctionGraphVertexAttributes newSettings = cloneSettings(originalGraph, program);
		Function function = originalGraph.getFunction();
		FunctionGraph newGraph = new FunctionGraph(function, newSettings, vertices, edges);

		newGraph.setOptions(originalGraph.getOptions());

		FGVertex entry = newGraph.getVertexForAddress(function.getEntryPoint());
		newGraph.setRootVertex(entry);

		return newGraph;
	}

	private static void cloneLayout(FunctionGraph originalGraph, FunctionGraph newGraph) {
		FGLayout originalLayout = originalGraph.getLayout();
		FGLayout newLayout = originalLayout.cloneLayout(newGraph);
		newGraph.setGraphLayout(newLayout);
	}

	private static Map<FGVertex, FGVertex> cloneVertices(Collection<FGVertex> vertices,
			FGController newController) {

		Map<FGVertex, FGVertex> map = new HashMap<>();

		for (FGVertex vertex : vertices) {
			FGVertex newVertex = vertex.cloneVertex(newController);
			map.put(vertex, newVertex);
		}

		return map;
	}

	private static Collection<FGEdge> cloneEdges(FunctionGraph currentGraph,
			Map<FGVertex, FGVertex> oldToNewCloneMap, Collection<FGEdge> originalEdges,
			FGController newController) {

		List<FGEdge> edges = new ArrayList<>();
		for (FGEdge edge : originalEdges) {
			FGVertex newStartVertex = oldToNewCloneMap.get(edge.getStart());
			FGVertex newVertex = oldToNewCloneMap.get(edge.getEnd());

			if (newStartVertex == null || newVertex == null) {
				Msg.debug(null, "no nulls!");
			}

			FGEdge newEdge = edge.cloneEdge(newStartVertex, newVertex);
			edges.add(newEdge);
		}
		return edges;
	}

	private static FunctionGraphVertexAttributes cloneSettings(FunctionGraph originalFunctionGraph,
			Program program) {
		originalFunctionGraph.saveSettings();
		return new FunctionGraphVertexAttributes(program);
	}

	/**
	 * Creates a new function graph for the given function
	 * 
	 * @param function the function to graph
	 * @param controller the controller needed by the function graph
	 * @param program the function's program
	 * @param monitor the task monitor
	 * @return the new graph
	 * @throws CancelledException if the task is cancelled via the monitor
	 */
	public static FGData createNewGraph(Function function, FGController controller, Program program,
			TaskMonitor monitor) throws CancelledException {

		FunctionGraph graph = createGraph(function, controller, monitor);
		if (graph.getVertices().size() == 0) {
			return new EmptyFunctionGraphData("No data in function: " + function.getName());
		}

		if (!isEntryPointValid(function, controller, monitor)) {
			return new EmptyFunctionGraphData(
				"No instruction at function entry point: " + function.getName());
		}

		FGVertex functionEntryVertex = graph.getVertexForAddress(function.getEntryPoint());
		graph.setRootVertex(functionEntryVertex);

		graph.setOptions(controller.getFunctionGraphOptions());

		// doing this here will keep the potentially slow work off of the Swing thread, as the
		// results are cached
		String errorMessage = layoutGraph(function, controller, graph, monitor);
		return new FGData(function, graph, errorMessage);
	}

	/*
	 * Returns true if the given function has an entry point that represents a valid instruction
	 * (cannot be undefined).
	 */
	private static boolean isEntryPointValid(Function function, FGController controller,
			TaskMonitor monitor) throws CancelledException {

		CodeBlockModel blockModel = new BasicBlockModel(controller.getProgram());

		CodeBlock[] codeBlock =
			blockModel.getCodeBlocksContaining(function.getEntryPoint(), monitor);

		if (codeBlock == null || codeBlock.length == 0) {
			monitor.setMessage("No instruction at function entry point.");
			return false;
		}

		return true;
	}

	private static String layoutGraph(Function function, FGController controller,
			FunctionGraph functionGraph, TaskMonitor monitor) throws CancelledException {

		if (!performSwingThreadRequiredWork(functionGraph)) {
			return null;// shouldn't happen
		}

		monitor.setMessage("Performing graph layout...");
		FGLayoutProvider layoutProvider = controller.getLayoutProvider();

		try {
			FGLayout layout = layoutProvider.getLayout(functionGraph, monitor);
			functionGraph.setGraphLayout(layout);
			return null;
		}
		catch (CancelledException ce) {
			throw ce;
		}
		catch (Exception e) {
			Msg.error(FunctionGraphFactory.class,
				"Exception performing graph layout for function " + function, e);
			controller.setStatusMessage("Problem performing graph layout--try another layout");
		}

		//
		// Setup a default/dummy layout
		//
		functionGraph.setGraphLayout(new EmptyLayout(functionGraph));

		return "Problem performing graph layout using the \"" + layoutProvider.getLayoutName() +
			"\" (try another layout)";
	}

	private static boolean performSwingThreadRequiredWork(FunctionGraph functionGraph) {
		final Collection<FGVertex> vertices = functionGraph.getVertices();
		try {
			SystemUtilities.runSwingNow(() -> {
				for (FGVertex v : vertices) {
					v.getComponent();
				}
			});
			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	private static boolean isEntry(CodeBlock codeBlock) {
		boolean isSource = true;
		try {
			CodeBlockReferenceIterator iter = codeBlock.getSources(TaskMonitor.DUMMY);
			while (iter.hasNext()) {
				isSource = false;
				if (iter.next().getFlowType().isCall()) {
					// any calls into a code block will make it an 'entry'
					return true;
				}
			}
		}
		catch (CancelledException e) {
			// will never happen, because I don't have a monitor
		}
		return isSource;
	}

	private static FunctionGraph createGraph(Function function, FGController controller,
			TaskMonitor monitor) throws CancelledException {

		BidiMap<CodeBlock, FGVertex> vertices = createVertices(function, controller, monitor);

		Collection<FGEdge> edges = createdEdges(vertices, controller, monitor);

		FunctionGraphVertexAttributes settings =
			new FunctionGraphVertexAttributes(controller.getProgram());
		FunctionGraph graph = new FunctionGraph(function, settings, vertices.values(), edges);

		for (FGVertex vertex : vertices.values()) {
			vertex.setVertexType(getVertexType(graph, vertex));
		}

		return graph;
	}

	private static Collection<FGEdge> createdEdges(BidiMap<CodeBlock, FGVertex> vertices,
			FGController controller, TaskMonitor monitor) throws CancelledException {

		List<FGEdge> edges = new ArrayList<>();
		for (FGVertex startVertex : vertices.values()) {
			Collection<FGEdge> vertexEdges =
				getEdgesForStartVertex(vertices, startVertex, controller, monitor);

			edges.addAll(vertexEdges);
		}

		return edges;
	}

	private static Collection<FGEdge> getEdgesForStartVertex(
			BidiMap<CodeBlock, FGVertex> blockToVertexMap, FGVertex startVertex,
			FGController controller, TaskMonitor monitor) throws CancelledException {

		List<FGEdge> edges = new ArrayList<>();
		CodeBlock codeBlock = blockToVertexMap.getKey(startVertex);
		CodeBlockReferenceIterator destinations = codeBlock.getDestinations(monitor);
		for (; destinations.hasNext();) {
			CodeBlockReference reference = destinations.next();
			CodeBlock destinationBlock = reference.getDestinationBlock();
			FGVertex destinationVertex = blockToVertexMap.get(destinationBlock);
			if (destinationVertex == null) {
				continue;// no vertex means the code block is not in our function
			}

			edges.add(new FGEdgeImpl(startVertex, destinationVertex, reference.getFlowType(),
				controller.getFunctionGraphOptions()));
		}
		return edges;
	}

	private static BidiMap<CodeBlock, FGVertex> createVertices(Function function,
			final FGController controller, TaskMonitor monitor) throws CancelledException {

		BidiMap<CodeBlock, FGVertex> vertices = new DualHashBidiMap<>();
		CodeBlockModel blockModel = new BasicBlockModel(controller.getProgram());

		AddressSetView addresses = function.getBody();
		CodeBlockIterator iterator = blockModel.getCodeBlocksContaining(addresses, monitor);
		monitor.initialize(addresses.getNumAddresses());

		for (; iterator.hasNext();) {
			CodeBlock codeBlock = iterator.next();

			FlowType flowType = codeBlock.getFlowType();
			boolean isEntry = isEntry(codeBlock);
			Address cbStart = codeBlock.getFirstStartAddress();
			if (cbStart.equals(function.getEntryPoint())) {
				isEntry = true;
			}

			FGVertex vertex =
				new ListingFunctionGraphVertex(controller, codeBlock, flowType, isEntry);
			vertices.put(codeBlock, vertex);

			long blockAddressCount = codeBlock.getNumAddresses();
			long currentProgress = monitor.getProgress();
			monitor.setProgress(currentProgress + blockAddressCount);
		}

		return vertices;
	}

	private static FGVertexType getVertexType(Graph<FGVertex, FGEdge> graph, FGVertex v) {

		boolean isEntry = v.isEntry();
		boolean isExit = false;

		FlowType flowType = v.getFlowType();
		if (flowType.isTerminal()) {
			isExit = true;
		}

		if (graph.getOutEdges(v).isEmpty()) {
			isExit = true;
		}

		FGVertexType type = BODY;
		if (isEntry) {
			if (isExit) {
				type = SINGLETON;
			}
			else {
				type = ENTRY;
			}
		}
		else if (isExit) {
			type = EXIT;
		}
		return type;
	}

}
