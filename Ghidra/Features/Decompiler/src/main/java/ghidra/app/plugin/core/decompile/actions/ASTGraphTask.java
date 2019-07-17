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

import ghidra.app.services.GraphService;
import ghidra.program.model.address.Address;
import ghidra.program.model.graph.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.task.*;

import java.util.Iterator;

public class ASTGraphTask extends Task {

	static final int CONTROL_FLOW_GRAPH = 0;
	static final int DATA_FLOW_GRAPH = 1;

	private static final String[] GRAPH_TYPES =
		new String[] { "AST Control Flow", "AST Data Flow" };

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

	private GraphService graphService;
	private boolean newGraph;
	private int codeLimitPerBlock;
	private Address location;
	private HighFunction hfunction;
	private int graphType;

	private int uniqueNum = 0;
	private TaskListener listener;

	public ASTGraphTask(GraphService graphService, boolean newGraph, int codeLimitPerBlock,
			Address location, HighFunction hfunction, int graphType) {
		super("Graph " + GRAPH_TYPES[graphType], true, false, true);

		this.graphService = graphService;
		this.newGraph = newGraph;
		this.codeLimitPerBlock = codeLimitPerBlock;
		this.location = location;
		this.hfunction = hfunction;
		this.graphType = graphType;

		this.listener = new TaskListener() {
			@Override
			public void taskCancelled(Task task) {
				// don't care
			}

			@Override
			public void taskCompleted(Task task) {
				try {
					GraphDisplay graphDisplay =
						ASTGraphTask.this.graphService.getGraphDisplay(false);
					if (graphDisplay != null) {
						graphDisplay.popup();
					}
				}
				catch (GraphException e) {
					// the programmer was too lazy to handle this
				}
			}
		};
		addTaskListener(listener);
	}

	@Override
	public void run(TaskMonitor monitor) {

		// get a new graph
		GraphData graph = graphService.createGraphContent();
		if (graph == null)
			return;

		ASTGraphSelectionHandler handler = null;
		try {
			monitor.setMessage("Computing Graph...");
			if (graphType == DATA_FLOW_GRAPH) {
				createDataFlowGraph(graph, monitor);
			}
			else {
				createControlFlowGraph(graph, monitor);
			}
			handler = new ASTGraphSelectionHandler(graphService, hfunction, graphType);
		}
		catch (CancelledException e1) {
			return;
		}

		GraphDisplay display;
		try {
			monitor.setMessage("Obtaining handle to graph provider...");
			display = graphService.getGraphDisplay(newGraph);
			if (monitor.isCancelled())
				return;
			monitor.setCancelEnabled(false);

			if (!newGraph) {
				display.clear();
			}
			display.setSelectionHandler(handler);

			monitor.setMessage("Rendering Graph...");
			display.defineVertexAttribute(CODE_ATTRIBUTE);
			display.defineVertexAttribute(SYMBOLS_ATTRIBUTE);

			display.setGraphData(graph);

			display.setVertexLabel(CODE_ATTRIBUTE, GraphDisplay.ALIGN_LEFT, 12, true,
				graphType == CONTROL_FLOW_GRAPH ? (codeLimitPerBlock + 1) : 1);

			// set the graph location
			if (location != null) {
				display.locate(location, false);
			}

		}
		catch (GraphException e) {
			Msg.showError(this, null, "Graph Error", e.getMessage());
		}
	}

	protected void createDataFlowGraph(GraphData graph, TaskMonitor monitor)
			throws CancelledException {
		Iterator<PcodeOpAST> opIter = hfunction.getPcodeOps();
		while (opIter.hasNext()) {
			monitor.checkCanceled();
			graphOpData(graph, opIter.next(), monitor);
		}
	}

	private void graphOpData(GraphData graph, PcodeOpAST op, TaskMonitor monitor)
			throws CancelledException {

		// TODO: Dropped INDIRECT pcode ops ??

		if (op == null || op.getOpcode() == PcodeOp.INDIRECT) {
			return;
		}

		GraphVertex opVertex = getOpVertex(graph, op, monitor);

		Varnode output = op.getOutput();
		if (output != null) {
			opVertex = getOpVertex(graph, op, monitor);
			GraphVertex outVertex = getDataVertex(graph, output, monitor);
			graph.createEdge(Integer.toString(++uniqueNum), opVertex, outVertex);
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
				GraphVertex inVertex = getDataVertex(graph, input, monitor);
				graph.createEdge(Integer.toString(++uniqueNum), inVertex, opVertex);
				// TODO: set edge attributes ??
			}
		}
	}

	private GraphVertex getOpVertex(GraphData graph, PcodeOpAST op, TaskMonitor monitor) {

		String key = "O_" + Integer.toString(op.getSeqnum().getTime());
		GraphVertex vertex = graph.getVertex(key);

		if (vertex == null) {
			vertex = graph.createVertex(key, key);
			setOpVertexAttributes(vertex, op);
		}
		return vertex;
	}

	private void setOpVertexAttributes(GraphVertex vertex, PcodeOpAST op) {

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

	private GraphVertex getDataVertex(GraphData graph, Varnode node, TaskMonitor monitor) {

		// TODO: Missing Varnode unique ID ??

		GraphVertex vertex = null;
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
			vertex = graph.createVertex(key, key);
			setVarnodeVertexAttributes(vertex, node);
		}
		return vertex;
	}

	private void setVarnodeVertexAttributes(GraphVertex vertex, Varnode node) {

		String label = "";
		HighVariable var = node.getHigh();
		if (var != null) {
			label = var.getName() + ": ";
		}
		label += translateVarnode(node, false);
		vertex.setAttribute(CODE_ATTRIBUTE, label);
		vertex.setAttribute(VERTEX_TYPE_ATTRIBUTE, DATA_NODE);
	}

	protected void createControlFlowGraph(GraphData graph, TaskMonitor monitor)
			throws CancelledException {
		Iterator<PcodeBlockBasic> pblockIter = hfunction.getBasicBlocks().iterator();
		while (pblockIter.hasNext()) {
			monitor.checkCanceled();
			graphPcodeBlock(graph, pblockIter.next(), monitor);
		}
	}

	private void graphPcodeBlock(GraphData graph, PcodeBlock pblock, TaskMonitor monitor)
			throws CancelledException {

		if (pblock == null) {
			return;
		}

		GraphVertex fromVertex = getBlockVertex(graph, pblock, monitor);

		int outCnt = pblock.getOutSize();
		for (int i = 0; i < outCnt; i++) {
			monitor.checkCanceled();
			PcodeBlock outPBlock = pblock.getOut(i);
			GraphVertex toVertex = getBlockVertex(graph, outPBlock, monitor);
			graph.createEdge(Integer.toString(++uniqueNum), fromVertex, toVertex);
			// TODO: set edge attributes ??
		}
	}

	private GraphVertex getBlockVertex(GraphData graph, PcodeBlock pblock, TaskMonitor monitor) {

		String key = Integer.toString(pblock.getIndex());
		GraphVertex vertex = graph.getVertex(key);

		if (vertex == null) {
			vertex = graph.createVertex(key, key);
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

	private void setBlockVertexAttributes(GraphVertex vertex, PcodeBlockBasic basicBlk) {

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

//	private void assignVertexSymbols(GraphVertex vertex, Address addr) {
//		Symbol[] symbols = function.getProgram().getSymbolTable().getSymbols(addr);
//		if (symbols.length != 0) {
//			StringBuffer buf = new StringBuffer();
//			for (int i = 0; i < symbols.length; i++) {
//				if (i != 0) {
//					buf.append('\n');
//				}
//				buf.append(symbols[i].getName());
//			}
//			vertex.setAttribute(SYMBOLS_ATTRIBUTE, buf.toString());	
//		}
//	}

}
