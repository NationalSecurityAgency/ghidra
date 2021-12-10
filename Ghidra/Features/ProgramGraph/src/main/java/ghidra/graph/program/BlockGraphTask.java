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

import static ghidra.graph.ProgramGraphType.*;

import java.util.*;

import docking.action.builder.ActionBuilder;
import docking.widgets.EventTrigger;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.util.AddEditDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.*;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.service.graph.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * <CODE>GraphTask</CODE> is a threaded task creating either a block or call graph.
 */
public class BlockGraphTask extends Task {

	private static final String CODE_ATTRIBUTE = "Code";
	private static final String SYMBOLS_ATTRIBUTE = "Symbols";

	protected static final String PROGRESS_DIALOG_TITLE = "Graphing Program";
	protected static final String INIT_PROGRESS_MSG = "Graphing Program...";

	private boolean graphEntryPointNexus = false;
	private boolean showCode = false;
	private int codeLimitPerBlock = 10;

	private ColorizingService colorizingService;

	private final static String ENTRY_NEXUS_NAME = "Entry Points";
	private static final int MAX_SYMBOLS = 10;
	private CodeBlockModel blockModel;
	private AddressSetView selection;
	private ProgramLocation location;
	private GraphDisplayProvider graphProvider;
	private boolean reuseGraph;
	private boolean appendGraph;
	private PluginTool tool;
	private Program program;
	private AddressSetView graphScope;
	private String graphTitle;
	private ProgramGraphType graphType;

	public BlockGraphTask(ProgramGraphType graphType,
			boolean graphEntryPointNexus, boolean reuseGraph, boolean appendGraph,
			PluginTool tool, ProgramSelection selection, ProgramLocation location,
			CodeBlockModel blockModel, GraphDisplayProvider graphProvider) {

		super("Graph Program", true, false, true);
		this.graphType = graphType;
		this.graphEntryPointNexus = graphEntryPointNexus;
		this.showCode = graphType instanceof CodeFlowGraphType;
		this.reuseGraph = reuseGraph;
		this.appendGraph = appendGraph;
		this.tool = tool;
		this.blockModel = blockModel;
		this.graphProvider = graphProvider;
		this.colorizingService = tool.getService(ColorizingService.class);
		this.selection = selection;
		this.location = location;
		this.program = blockModel.getProgram();
		this.graphTitle = graphType.getName() + ": ";
	}

	/**
	 * Runs the move memory operation.
	 */
	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		this.graphScope = getGraphScopeAndGenerateGraphTitle();
		AttributedGraph graph = createGraph(graphTitle);
		monitor.setMessage("Generating Graph...");
		try {
			GraphDisplay display =
				graphProvider.getGraphDisplay(reuseGraph, monitor);
			GraphDisplayOptions graphOptions = new ProgramGraphDisplayOptions(graphType, tool);
			if (showCode) { // arrows need to be bigger as this generates larger vertices
				graphOptions.setArrowLength(30);
			}

			BlockModelGraphDisplayListener listener =
				new BlockModelGraphDisplayListener(tool, blockModel, display);
			addActions(display, v -> listener.getAddress(v));
			display.setGraphDisplayListener(listener);

			if (showCode) {
				graphOptions.setVertexLabelOverrideAttributeKey(CODE_ATTRIBUTE);
			}
			display.setGraph(graph, graphOptions, graphTitle, appendGraph, monitor);

			if (location != null) {
				// initialize the graph location, but don't have the graph send an event
				AttributedVertex vertex = listener.getVertex(location.getAddress());
				display.setFocusedVertex(vertex, EventTrigger.INTERNAL_ONLY);
			}
			if (selection != null && !selection.isEmpty()) {
				Set<AttributedVertex> selectedVertices = listener.getVertices(selection);
				if (selectedVertices != null) {
					// initialize the graph selection, but don't have the graph send an event
					display.selectVertices(selectedVertices, EventTrigger.INTERNAL_ONLY);
				}
			}
		}
		catch (GraphException e) {
			if (!monitor.isCancelled()) {
				Msg.showError(this, null, "Graphing Error", e.getMessage());
			}
		}
	}

	private void addActions(GraphDisplay display,
			java.util.function.Function<AttributedVertex, Address> addressFunction) {

		display.addAction(new ActionBuilder("Rename Symbol", "Block Graph")
				.popupMenuPath("Rename Symbol")
				.withContext(VertexGraphActionContext.class)
				.helpLocation(new HelpLocation("ProgramGraphPlugin", "Rename_Symbol"))
				// only enable action when vertex corresponds to an address
				.enabledWhen(c -> addressFunction.apply(c.getClickedVertex()) != null)
				.onAction(c -> updateVertexName(addressFunction, c))
				.build());
	}

	private void updateVertexName(
			java.util.function.Function<AttributedVertex, Address> addressFunction,
			VertexGraphActionContext context) {

		AttributedVertex vertex = context.getClickedVertex();
		Address address = addressFunction.apply(vertex);
		Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);

		if (symbol == null) {
			AddEditDialog dialog = new AddEditDialog("Create Label", tool);
			dialog.addLabel(address, program, context.getComponentProvider());
		}
		else {
			AddEditDialog dialog = new AddEditDialog("Edit Label", tool);
			dialog.editLabel(symbol, program, context.getComponentProvider());
		}
	}

	/**
	 * Set the maximum number of code lines which will be used per block when
	 * showCode is enabled.
	 * @param maxLines maximum number of code lines
	 */
	public void setCodeLimitPerBlock(int maxLines) {
		codeLimitPerBlock = maxLines;
	}

	protected AttributedGraph createGraph(String name) throws CancelledException {
		int blockCount = 0;
		AttributedGraph graph = new AttributedGraph(name, graphType);

		CodeBlockIterator it = getBlockIterator();
		List<AttributedVertex> entryPoints = new ArrayList<>();

		while (it.hasNext()) {
			CodeBlock curBB = it.next();
			Address start = graphBlock(graph, curBB, entryPoints);

			if (start != null && (++blockCount % 50) == 0) {
				taskMonitor.setMessage("Process Block: " + start.toString());
			}
		}

		// if option is set and there is more than one entry point vertex, create fake entry node
		// and connect to each entry point vertex
		if (graphEntryPointNexus && entryPoints.size() > 1) {
			addEntryEdges(graph, entryPoints);
		}

		return graph;
	}

	private CodeBlockIterator getBlockIterator() throws CancelledException {
		return blockModel.getCodeBlocksContaining(graphScope, taskMonitor);
	}

	private AddressSetView getGraphScopeAndGenerateGraphTitle() {
		if (selection != null && !selection.isEmpty()) {
			graphTitle += selection.getMinAddress().toString();
			return selection;
		}
		Function function = getContainingFunction(location);
		if (function != null) {
			graphTitle += function.getName();
			if (isCallGraph()) {
				return getScopeForCallGraph(function);
			}
			return function.getBody();
		}
		graphTitle += "(Entire Program)";
		return blockModel.getProgram().getMemory();
	}

	private boolean isCallGraph() {
		return blockModel instanceof SubroutineBlockModel;
	}

	private AddressSetView getScopeForCallGraph(Function function) {
		AddressSet set = new AddressSet();
		set.add(function.getBody());
		try {
			CodeBlock block = blockModel.getCodeBlockAt(function.getEntryPoint(), taskMonitor);
			CodeBlockReferenceIterator it = blockModel.getDestinations(block, taskMonitor);
			while (it.hasNext()) {
				CodeBlockReference next = it.next();
				set.add(next.getDestinationBlock());
			}
			it = blockModel.getSources(block, taskMonitor);
			while (it.hasNext()) {
				CodeBlockReference next = it.next();
				set.add(next.getSourceBlock());
			}
		}
		catch (CancelledException e) {
			// just return, the task is being cancelled.
		}

		return set;
	}

	private Function getContainingFunction(ProgramLocation cursorLocation) {
		if (cursorLocation == null) {
			return null;
		}
		Address address = cursorLocation.getAddress();
		if (address == null) {
			return null;
		}
		return blockModel.getProgram().getFunctionManager().getFunctionContaining(address);
	}

	private Address graphBlock(AttributedGraph graph, CodeBlock curBB,
			List<AttributedVertex> entries)
			throws CancelledException {

		Address[] startAddrs = curBB.getStartAddresses();

		if (startAddrs == null || startAddrs.length == 0) {
			Msg.error(this, "Block not graphed, missing start address: " + curBB.getMinAddress());
			return null;
		}

		AttributedVertex vertex = graphBasicBlock(graph, curBB);

		if (graphEntryPointNexus && hasExternalEntryPoint(startAddrs)) {
			entries.add(vertex);
		}
		return startAddrs[0];
	}

	private boolean hasExternalEntryPoint(Address[] startAddrs) {
		SymbolTable symbolTable = program.getSymbolTable();
		for (Address address : startAddrs) {
			if (symbolTable.isExternalEntryPoint(address)) {
				return true;
			}
		}
		return false;
	}

	private void addEntryEdges(AttributedGraph graph, List<AttributedVertex> entries) {
		AttributedVertex entryNexusVertex = getEntryNexusVertex(graph);
		for (AttributedVertex vertex : entries) {
			AttributedEdge edge = graph.addEdge(entryNexusVertex, vertex);
			edge.setAttribute("EdgeType", ENTRY_NEXUS);
		}
	}

	protected AttributedVertex graphBasicBlock(AttributedGraph graph, CodeBlock curBB)
			throws CancelledException {

		AttributedVertex fromVertex = getBasicBlockVertex(graph, curBB);

		// for each destination block
		//  create a vertex if it doesn't exit and add an edge to the destination vertex
		CodeBlockReferenceIterator refIter = curBB.getDestinations(taskMonitor);
		while (refIter.hasNext()) {
			CodeBlockReference cbRef = refIter.next();

			CodeBlock db = cbRef.getDestinationBlock();
			if (db == null) {
				continue; // must be a reference to a data block
			}

			// don't include destination if it does not overlap selection
			// always include if selection is empty
			if (graphScope != null && !graphScope.isEmpty() && !graphScope.intersects(db)) {
				continue;
			}

			AttributedVertex toVertex = getBasicBlockVertex(graph, db);
			if (toVertex == null) {
				continue;
			}

			//	put the edge in the graph
			AttributedEdge newEdge = graph.addEdge(fromVertex, toVertex);

			// set it's attributes (really its name)
			setEdgeAttributes(newEdge, cbRef);
			setEdgeColor(newEdge, fromVertex, toVertex);

		}
		return fromVertex;
	}

	private void setEdgeColor(AttributedEdge edge, AttributedVertex fromVertex,
			AttributedVertex toVertex) {
		// color the edge: first on the 'from' vertex, then try to 'to' vertex
		String fromColor = fromVertex.getAttribute("Color");
		String toColor = toVertex.getAttribute("Color");
		if (fromColor != null || toColor != null) {
			if (fromColor != null) {
				edge.setAttribute("Color", fromColor);
			}
			else if (toColor != null) {
				edge.setAttribute("Color", toColor);
			}
		}

	}

	private String getVertexId(CodeBlock bb) {
		// vertex has attributes of Name       = Label
		//                          Address    = address of blocks start
		//                          VertexType = flow type of vertex
		Address addr = bb.getFirstStartAddress();
		if (addr.isExternalAddress()) {
			Symbol s = bb.getModel().getProgram().getSymbolTable().getPrimarySymbol(addr);
			return s.getName(true);
		}
		return addr.toString();
	}

	protected AttributedVertex getBasicBlockVertex(AttributedGraph graph, CodeBlock bb)
			throws CancelledException {

		String vertexId = getVertexId(bb);
		AttributedVertex vertex = graph.getVertex(vertexId);

		if (vertex != null) {
			return vertex;
		}

		String vertexName = bb.getName();
		vertex = graph.addVertex(vertexId, vertexName);

		// add attributes for this vertex -
		setVertexAttributes(vertex, bb, vertexName.equals(vertexId) ? false : isEntryNode(bb));

		if (showCode) {
			addSymbolAttribute(vertex, bb);
			addCodeAttribute(vertex, bb);
		}

		return vertex;
	}

	private void addCodeAttribute(AttributedVertex vertex, CodeBlock bb) {
		if (!bb.getMinAddress().isMemoryAddress()) {
			vertex.setAttribute(CODE_ATTRIBUTE, vertex.getAttribute(SYMBOLS_ATTRIBUTE));
		}

		Listing listing = program.getListing();
		CodeUnitIterator cuIter = listing.getCodeUnits(bb, true);
		int cnt = 0;
		int maxMnemonicFieldLen = 0;
		StringBuffer buf = new StringBuffer();
		while (cuIter.hasNext()) {
			CodeUnit cu = cuIter.next();
			if (cnt != 0) {
				buf.append('\n');
			}
			String line = cu.toString();
			int ix = line.indexOf(' ');
			if (ix > maxMnemonicFieldLen) {
				maxMnemonicFieldLen = ix;
			}
			buf.append(line);
			if (++cnt == codeLimitPerBlock) {
				buf.append("\n...");
				break;
			}
		}
		vertex.setAttribute(CODE_ATTRIBUTE, adjustCode(buf, maxMnemonicFieldLen + 1));
	}

	private void addSymbolAttribute(AttributedVertex vertex, CodeBlock bb) {
		SymbolIterator it = program.getSymbolTable().getSymbolsAsIterator(bb.getMinAddress());
		int count = 0;
		if (it.hasNext()) {
			StringBuffer buf = new StringBuffer();
			for (Symbol symbol : it) {
				if (count != 0) {
					buf.append('\n');
				}
				// limit the number of symbols to include (there can be a ridiculous # of symbols) 
				if (count++ > MAX_SYMBOLS) {
					buf.append("...");
					break;
				}
				buf.append(symbol.getName());
			}
			vertex.setAttribute(SYMBOLS_ATTRIBUTE, buf.toString());
		}

	}

	private String adjustCode(StringBuffer buf, int mnemonicFieldLen) {
		if (mnemonicFieldLen <= 1) {
			return buf.toString();
		}
		int ix = 0;
		char[] pad = new char[mnemonicFieldLen];
		Arrays.fill(pad, ' ');
		while (ix < buf.length()) {
			int eolIx = buf.indexOf("\n", ix);
			if (eolIx < 0) {
				eolIx = buf.length();
			}
			int padIx = buf.indexOf(" ", ix);
			if (padIx > 0 && padIx < eolIx) {
				int padSize = mnemonicFieldLen - padIx + ix;
				if (padSize > 0) {
					buf.insert(padIx, pad, 0, padSize);
					eolIx += padSize;
				}
			}
			ix = eolIx + 1;
		}
		return buf.toString();
	}

	/**
	 * Determine if the specified block is an entry node.
	 * @param block the basic block to test
	 * @return true  if the specified block is an entry node.
	 * @throws CancelledException if the operation is cancelled
	 */
	protected boolean isEntryNode(CodeBlock block) throws CancelledException {
		CodeBlockReferenceIterator iter = block.getSources(taskMonitor);
		boolean isSource = true;
		while (iter.hasNext()) {
			isSource = false;
			if (iter.next().getFlowType().isCall()) {
				return true;
			}
		}
		return isSource;
	}

	protected void setEdgeAttributes(AttributedEdge edge, CodeBlockReference ref) {
		edge.setEdgeType(ProgramGraphType.getEdgeType(ref.getFlowType()));
	}

	protected void setVertexAttributes(AttributedVertex vertex, CodeBlock bb, boolean isEntry) {

		String vertexType = BODY;

		Address firstStartAddress = bb.getFirstStartAddress();
		if (firstStartAddress.isExternalAddress()) {
			vertexType = EXTERNAL;
		}
		else if (isEntry) {
			vertexType = ENTRY;
		}
		else {
			FlowType flowType = bb.getFlowType();
			if (flowType.isTerminal()) {
				vertexType = EXIT;
			}
			else if (flowType.isComputed()) {
				vertexType = SWITCH;
			}
			else if (flowType == RefType.INDIRECTION) {
				vertexType = DATA;
			}
			else if (flowType == RefType.INVALID) {
				vertexType = BAD;
			}
		}
		vertex.setVertexType(vertexType);
	}

	private AttributedVertex getEntryNexusVertex(AttributedGraph graph) {
		AttributedVertex vertex = graph.getVertex(ENTRY_NEXUS_NAME);
		if (vertex == null) {
			vertex = graph.addVertex(ENTRY_NEXUS_NAME, ENTRY_NEXUS_NAME);
			vertex.setAttribute("VertexType", ENTRY_NEXUS);
		}
		return vertex;
	}
}
