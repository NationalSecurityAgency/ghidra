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
package ghidra.app.plugin.core.decompile.actions;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import docking.widgets.EventTrigger;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.service.graph.*;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import static ghidra.service.graph.GraphDisplay.*;

public class ASTGraphTask extends Task {
	enum GraphType {
		CONTROL_FLOW_GRAPH("AST Control Flow"), DATA_FLOW_GRAPH("AST Data Flow");
		private String name;

		GraphType(String name) {
			this.name = name;
		}

		public String getName() {
			return name;
		}
	}

	private static final String CODE_ATTRIBUTE = "Code";
	private static final String SYMBOLS_ATTRIBUTE = "Symbols";
	private static final String VERTEX_TYPE_ATTRIBUTE = "VertexType";

	// Vertex Types
	private final static String ENTRY_NODE = "Entry";
	// "1";       // beginning of a block, someone calls it
	private final static String BODY_NODE = "Body";
	// "2";       // Body block, no flow
	private final static String EXIT_NODE = "Exit";
	// "3";       // Terminator
	private final static String SWITCH_NODE = "Switch";
	// "4";       // Switch/computed jump
	private final static String BAD_NODE = "Bad";
	// "5";       // Bad destination
	private final static String DATA_NODE = "Data";
	// "6";       // Data Node, used for indirection

	private GraphDisplayBroker graphService;
	private boolean newGraph;
	private int codeLimitPerBlock;
	private Address location;
	private HighFunction hfunction;
	private GraphType graphType;

	private int uniqueNum = 0;
	private PluginTool tool;

	public ASTGraphTask(GraphDisplayBroker graphService, boolean newGraph, int codeLimitPerBlock,
			Address location, HighFunction hfunction, GraphType graphType, PluginTool tool) {
		super("Graph " + graphType.getName(), true, false, true);

		this.graphService = graphService;
		this.newGraph = newGraph;
		this.codeLimitPerBlock = codeLimitPerBlock;
		this.location = location;
		this.hfunction = hfunction;
		this.graphType = graphType;
		this.tool = tool;
	}

	@Override
	public void run(TaskMonitor monitor) {

		// get a new graph
		AttributedGraph graph = new AttributedGraph();

		try {
			monitor.setMessage("Computing Graph...");
			if (graphType == GraphType.DATA_FLOW_GRAPH) {
				createDataFlowGraph(graph, monitor);
			}
			else {
				createControlFlowGraph(graph, monitor);
			}
			Map<String, String> properties = new HashMap<>();
			properties.put(SELECTED_VERTEX_COLOR, "0xFF1493");
			properties.put(SELECTED_EDGE_COLOR, "0xFF1493");
			properties.put(INITIAL_LAYOUT_ALGORITHM, "Hierarchical MinCross Coffman Graham");
			properties.put(ENABLE_EDGE_SELECTION, "true");
			GraphDisplay display = graphService.getDefaultGraphDisplay(!newGraph, properties, monitor);
			ASTGraphDisplayListener displayListener =
				new ASTGraphDisplayListener(tool, display, hfunction, graphType);
			display.setGraphDisplayListener(displayListener);

			monitor.setMessage("Obtaining handle to graph provider...");
			if (monitor.isCancelled()) {
				return;
			}
			monitor.setCancelEnabled(false);

			monitor.setMessage("Rendering Graph...");
			display.defineVertexAttribute(CODE_ATTRIBUTE);
			display.defineVertexAttribute(SYMBOLS_ATTRIBUTE);

			display.setVertexLabelAttribute(CODE_ATTRIBUTE, GraphDisplay.ALIGN_LEFT, 12, true,
				graphType == GraphType.CONTROL_FLOW_GRAPH ? (codeLimitPerBlock + 1) : 1);

			String description =
				graphType == GraphType.DATA_FLOW_GRAPH ? "AST Data Flow" : "AST Control Flow";
			description = description + " for " + hfunction.getFunction().getName();
			display.setGraph(graph, description, false, monitor);
			setGraphLocation(display, displayListener);
		}
		catch (GraphException e) {
			Msg.showError(this, null, "Graph Error", e.getMessage());
		}
		catch (CancelledException e1) {
			return;
		}

	}

	private void setGraphLocation(GraphDisplay display, ASTGraphDisplayListener displayListener) {
		if (location == null) {
			return;
		}

		AttributedVertex vertex = displayListener.getVertex(location);
		if (vertex == null) {
			return; // location not in graph
		}

		// update graph location, but don't have it send out event
		display.setFocusedVertex(vertex, EventTrigger.INTERNAL_ONLY);
	}

	protected void createDataFlowGraph(AttributedGraph graph, TaskMonitor monitor)
			throws CancelledException {
		Iterator<PcodeOpAST> opIter = hfunction.getPcodeOps();
		while (opIter.hasNext()) {
			monitor.checkCanceled();
			graphOpData(graph, opIter.next(), monitor);
		}
	}

	private void graphOpData(AttributedGraph graph, PcodeOpAST op, TaskMonitor monitor)
			throws CancelledException {

		// TODO: Dropped INDIRECT pcode ops ??

		if (op == null || op.getOpcode() == PcodeOp.INDIRECT) {
			return;
		}

		AttributedVertex opVertex = getOpVertex(graph, op, monitor);

		Varnode output = op.getOutput();
		if (output != null) {
			opVertex = getOpVertex(graph, op, monitor);
			AttributedVertex outVertex = getDataVertex(graph, output, monitor);
			graph.addEdge(opVertex, outVertex);
			// TODO: set edge attributes ??
		}

		int start = 0;
		int stop = op.getNumInputs() - 1;
		switch (op.getOpcode()) {
			case PcodeOp.LOAD:
			case PcodeOp.STORE:
			case PcodeOp.BRANCH:
			case PcodeOp.CALL:
				start = 1;
				break;
			case PcodeOp.INDIRECT:
				stop = 1;
				break;
		}

		for (int i = start; i <= stop; i++) {
			monitor.checkCanceled();
			Varnode input = op.getInput(i);
			if (input != null) {
				if (opVertex == null) {
					opVertex = getOpVertex(graph, op, monitor);
				}
				AttributedVertex inVertex = getDataVertex(graph, input, monitor);
				graph.addEdge(inVertex, opVertex);
				// TODO: set edge attributes ??
			}
		}
	}

	private AttributedVertex getOpVertex(AttributedGraph graph, PcodeOpAST op,
			TaskMonitor monitor) {

		String key = "O_" + Integer.toString(op.getSeqnum().getTime());
		AttributedVertex vertex = graph.getVertex(key);

		if (vertex == null) {
			vertex = graph.addVertex(key, key);
			setOpVertexAttributes(vertex, op);
		}
		return vertex;
	}

	private void setOpVertexAttributes(AttributedVertex vertex, PcodeOpAST op) {

		vertex.setAttribute(CODE_ATTRIBUTE, formatOpMnemonic(op));

		String vertexType = BODY_NODE;
		switch (op.getOpcode()) {
			case PcodeOp.BRANCH:
			case PcodeOp.BRANCHIND:
			case PcodeOp.CBRANCH:
			case PcodeOp.CALL:
			case PcodeOp.CALLIND:
				vertexType = SWITCH_NODE;
				break;
			case PcodeOp.RETURN:
				vertexType = EXIT_NODE;
				break;
		}
		vertex.setAttribute(VERTEX_TYPE_ATTRIBUTE, vertexType);
	}

	private AttributedVertex getDataVertex(AttributedGraph graph, Varnode node,
			TaskMonitor monitor) {

		// TODO: Missing Varnode unique ID ??

		AttributedVertex vertex = null;
		HighVariable var = node.getHigh();
		String key;
		if (var != null) {
			key = "V_" + var.getName();
			vertex = graph.getVertex(key);
		}
		else {
			key = Integer.toString(++uniqueNum);
		}

		if (vertex == null) {
			vertex = graph.addVertex(key, key);
			setVarnodeVertexAttributes(vertex, node);
		}
		return vertex;
	}

	private void setVarnodeVertexAttributes(AttributedVertex vertex, Varnode node) {

		String label = "";
		HighVariable var = node.getHigh();
		if (var != null) {
			label = var.getName() + ": ";
		}
		label += translateVarnode(node, false);
		vertex.setAttribute(CODE_ATTRIBUTE, label);
		vertex.setAttribute(VERTEX_TYPE_ATTRIBUTE, DATA_NODE);
	}

	protected void createControlFlowGraph(AttributedGraph graph, TaskMonitor monitor)
			throws CancelledException {
		Iterator<PcodeBlockBasic> pblockIter = hfunction.getBasicBlocks().iterator();
		while (pblockIter.hasNext()) {
			monitor.checkCanceled();
			graphPcodeBlock(graph, pblockIter.next(), monitor);
		}
	}

	private void graphPcodeBlock(AttributedGraph graph, PcodeBlock pblock, TaskMonitor monitor)
			throws CancelledException {

		if (pblock == null) {
			return;
		}

		AttributedVertex fromVertex = getBlockVertex(graph, pblock, monitor);

		int outCnt = pblock.getOutSize();
		for (int i = 0; i < outCnt; i++) {
			monitor.checkCanceled();
			PcodeBlock outPBlock = pblock.getOut(i);
			AttributedVertex toVertex = getBlockVertex(graph, outPBlock, monitor);
			graph.addEdge(fromVertex, toVertex);
			// TODO: set edge attributes ??
		}
	}

	private AttributedVertex getBlockVertex(AttributedGraph graph, PcodeBlock pblock,
			TaskMonitor monitor) {

		String key = Integer.toString(pblock.getIndex());
		AttributedVertex vertex = graph.getVertex(key);

		if (vertex == null) {
			vertex = graph.addVertex(key, key);
			if (pblock instanceof PcodeBlockBasic) {
				setBlockVertexAttributes(vertex, (PcodeBlockBasic) pblock);
			}
			else {
				vertex.setAttribute(CODE_ATTRIBUTE, "<???>");
				vertex.setAttribute(VERTEX_TYPE_ATTRIBUTE, BAD_NODE);
			}
		}
		return vertex;
	}

	private void setBlockVertexAttributes(AttributedVertex vertex, PcodeBlockBasic basicBlk) {

		// Build Pcode representation
		StringBuffer buf = new StringBuffer();
		int cnt = 0;
		Iterator<PcodeOp> opIter = basicBlk.getIterator();
		while (opIter.hasNext()) {
			PcodeOp op = opIter.next();
			if (buf.length() != 0) {
				buf.append('\n');
			}
			formatOp(op, buf);
			if (++cnt == codeLimitPerBlock) {
				buf.append("\n...");
				break;
			}
		}
		vertex.setAttribute(CODE_ATTRIBUTE, buf.toString());

		// Establish vertex type
		String vertexType = BODY_NODE;
		if (basicBlk.getInSize() == 0) {
			vertexType = ENTRY_NODE;
		}
		else {
			switch (basicBlk.getOutSize()) {
				case 0:
					vertexType = EXIT_NODE;
					break;
				case 1:
					vertexType = BODY_NODE;
					break;
				default:
					vertexType = SWITCH_NODE;
			}
		}
		vertex.setAttribute(VERTEX_TYPE_ATTRIBUTE, vertexType);
	}

	private String formatOpMnemonic(PcodeOp op) {

		String str = op.getMnemonic();
		Varnode output = op.getOutput();
		String size = null;
		if (output != null) {
			switch (output.getSize()) {
				case 1:
					size = "b";
					break;
				case 2:
					size = "w";
					break;
				case 4:
					size = "d";
					break;
				case 8:
					size = "q";
			}
			if (size != null) {
				str += "." + size;
			}
		}
		return str;
	}

	private void formatOp(PcodeOp op, StringBuffer buf) {
		Varnode output = op.getOutput();
		if (output != null) {
			buf.append(translateVarnode(output, true));
			buf.append(" = ");
		}
		buf.append(formatOpMnemonic(op));
		buf.append(" ");
		Varnode[] inputs = op.getInputs();
		for (int i = 0; i < inputs.length; i++) {
			if (i != 0) {
				buf.append(",");
			}
			buf.append(translateVarnode(inputs[i], true));
		}
	}

	private String translateVarnode(Varnode node, boolean useVarName) {
		if (node == null) {
			return "null";
		}
		Program p = hfunction.getFunction().getProgram();
		Address addr = node.getAddress();
		if (node.isConstant()) {
			return "#" + NumericUtilities.toHexString(addr.getOffset(), node.getSize());
		}
		else if (node.isUnique()) {
			return "u_" + Long.toHexString(addr.getOffset());
		}
		else if (addr.isRegisterAddress()) {
			Register r = p.getRegister(addr, node.getSize());
			if (r == null) {
				r = p.getRegister(addr);
			}
			if (r != null) {
				return r.getName();
			}
		}
		else if (addr.isStackAddress()) {
			if (useVarName) {
				HighVariable var = node.getHigh();
				if (var != null) {
					return var.getName();
				}
			}
			return "Stack[" + NumericUtilities.toSignedHexString(addr.getOffset()) + "]";
		}
		else if (addr.isMemoryAddress()) {
			return addr.toString(true);
		}
		return node.toString();
	}
}
