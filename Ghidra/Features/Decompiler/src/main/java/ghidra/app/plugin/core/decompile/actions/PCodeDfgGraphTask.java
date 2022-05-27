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

import static ghidra.app.plugin.core.decompile.actions.PCodeDfgDisplayOptions.*;

import java.util.*;

import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import ghidra.service.graph.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Task for creating PCode data flow graphs from decompiler output
 */
public class PCodeDfgGraphTask extends Task {

	private GraphDisplayBroker graphService;
	protected HighFunction hfunction;
	private AttributedGraph graph;
	private PluginTool tool;

	public PCodeDfgGraphTask(PluginTool tool, GraphDisplayBroker graphService,
			HighFunction hfunction) {
		super("Graph AST", true, false, true);
		this.graphService = graphService;
		this.hfunction = hfunction;
		this.tool = tool;
	}

	@Override
	public void run(TaskMonitor monitor) {
		try {
			buildAndDisplayGraph(monitor);
		}
		catch (GraphException e) {
			Msg.showError(this, null, "Graph Error",
				"Can't create graph display: " + e.getMessage(), e);
		}
		catch (CancelledException e1) {
			// do nothing
		}
	}

	private void buildAndDisplayGraph(TaskMonitor monitor)
			throws GraphException, CancelledException {

		GraphType graphType = new PCodeDfgGraphType();
		Function func = hfunction.getFunction();
		graph = new AttributedGraph("Data Flow Graph", graphType);
		buildGraph();

		GraphDisplay graphDisplay = graphService.getDefaultGraphDisplay(false, monitor);
		GraphDisplayOptions displayOptions = new PCodeDfgDisplayOptions(tool);

		String description = "AST Data Flow Graph For " + func.getName();
		graphDisplay.setGraph(graph, displayOptions, description, false, monitor);

		// Install a handler so the selection/location will map
		graphDisplay.setGraphDisplayListener(new PCodeDfgDisplayListener(tool, graphDisplay,
			hfunction, func.getProgram()));
	}

	protected void buildGraph() {

		HashMap<Integer, AttributedVertex> vertices = new HashMap<>();

		Iterator<PcodeOpAST> opiter = getPcodeOpIterator();
		while (opiter.hasNext()) {
			PcodeOpAST op = opiter.next();
			AttributedVertex o = createOpVertex(op);
			for (int i = 0; i < op.getNumInputs(); ++i) {
				int opcode = op.getOpcode();
				if ((i == 0) && ((opcode == PcodeOp.LOAD) || (opcode == PcodeOp.STORE))) {
					continue;
				}
				if ((i == 1) && (opcode == PcodeOp.INDIRECT)) {
					continue;
				}
				VarnodeAST vn = (VarnodeAST) op.getInput(i);
				if (vn != null) {
					AttributedVertex v = getVarnodeVertex(vertices, vn);
					createEdge(v, o);
				}
			}
			VarnodeAST outvn = (VarnodeAST) op.getOutput();
			if (outvn != null) {
				AttributedVertex outv = getVarnodeVertex(vertices, outvn);
				if (outv != null) {
					createEdge(o, outv);
				}
			}
		}
	}

	private String getVarnodeKey(VarnodeAST vn) {
		PcodeOp op = vn.getDef();
		String id;
		if (op != null) {
			id = op.getSeqnum().getTarget().toString(true) + " v " +
				Integer.toString(vn.getUniqueId());
		}
		else {
			id = "i v " + Integer.toString(vn.getUniqueId());
		}
		return id;
	}

	protected AttributedVertex createVarnodeVertex(VarnodeAST vn) {
		String name = vn.getAddress().toString(true);
		String id = getVarnodeKey(vn);
		String vertexType = PCodeDfgGraphType.DEFAULT_VERTEX;
		if (vn.isConstant()) {
			vertexType = PCodeDfgGraphType.CONSTANT;
		}
		else if (vn.isRegister()) {
			vertexType = PCodeDfgGraphType.REGISTER;
			Register reg =
				hfunction.getFunction().getProgram().getRegister(vn.getAddress(), vn.getSize());
			if (reg != null) {
				name = reg.getName();
			}
		}
		else if (vn.isUnique()) {
			vertexType = PCodeDfgGraphType.UNIQUE;
		}
		else if (vn.isPersistent()) {
			vertexType = PCodeDfgGraphType.PERSISTENT;
		}
		else if (vn.isAddrTied()) {
			vertexType = PCodeDfgGraphType.ADDRESS_TIED;
		}
		AttributedVertex vert = graph.addVertex(id, name);
		vert.setVertexType(vertexType);

		// if it is an input override the shape to be a triangle
		if (vn.isInput()) {
			vert.setAttribute(SHAPE_ATTRIBUTE, VertexShape.TRIANGLE_DOWN.getName());
		}
		return vert;
	}

	protected AttributedVertex getVarnodeVertex(Map<Integer, AttributedVertex> vertices,
			VarnodeAST vn) {
		AttributedVertex res;
		res = vertices.get(vn.getUniqueId());
		if (res == null) {
			res = createVarnodeVertex(vn);
			vertices.put(vn.getUniqueId(), res);
		}
		return res;
	}

	protected AttributedEdge createEdge(AttributedVertex in, AttributedVertex out) {
		AttributedEdge newEdge = graph.addEdge(in, out);
		newEdge.setEdgeType(PCodeDfgGraphType.DEFAULT_EDGE);
		return newEdge;
	}

	protected AttributedVertex createOpVertex(PcodeOpAST op) {
		String name = op.getMnemonic();
		String id = getOpKey(op);
		int opcode = op.getOpcode();
		if ((opcode == PcodeOp.LOAD) || (opcode == PcodeOp.STORE)) {
			Varnode vn = op.getInput(0);
			AddressSpace addrspace =
				hfunction.getFunction()
						.getProgram()
						.getAddressFactory()
						.getAddressSpace((int) vn.getOffset());
			name += ' ' + addrspace.getName();
		}
		else if (opcode == PcodeOp.INDIRECT) {
			Varnode vn = op.getInput(1);
			if (vn != null) {
				PcodeOp indOp = hfunction.getOpRef((int) vn.getOffset());
				if (indOp != null) {
					name += " (" + indOp.getMnemonic() + ')';
				}
			}
		}
		AttributedVertex vert = graph.addVertex(id, name);
		vert.setVertexType(PCodeDfgGraphType.OP);
		return vert;
	}

	protected Iterator<PcodeOpAST> getPcodeOpIterator() {
		Iterator<PcodeOpAST> opiter = hfunction.getPcodeOps();
		return opiter;
	}

	private String getOpKey(PcodeOpAST op) {
		SequenceNumber sq = op.getSeqnum();
		String id =
			sq.getTarget().toString(true) + " o " + Integer.toString(op.getSeqnum().getTime());
		return id;
	}
}
