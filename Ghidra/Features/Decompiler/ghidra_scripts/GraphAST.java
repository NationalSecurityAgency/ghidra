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
//Decompile the function at the cursor, then build data-flow graph (AST)
//@category PCode

import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.service.graph.*;
import ghidra.util.Msg;

public class GraphAST extends GhidraScript {
	protected static final String COLOR_ATTRIBUTE = "Color";
	protected static final String ICON_ATTRIBUTE = "Icon";

	private Function func;
	private AttributedGraph graph;
	protected HighFunction high;

	@Override
	public void run() throws Exception {
		PluginTool tool = state.getTool();
		if (tool == null) {
			println("Script is not running in GUI");
		}
		GraphDisplayBroker graphDisplayBroker = tool.getService(GraphDisplayBroker.class);
		if (graphDisplayBroker == null) {
			Msg.showError(this, tool.getToolFrame(), "GraphAST Error",
				"No graph display providers found: Please add a graph display provider to your tool");
			return;
		}

		func = this.getFunctionContaining(this.currentAddress);
		if (func == null) {
			Msg.showWarn(this, state.getTool().getToolFrame(), "GraphAST Error",
				"No Function at current location");
			return;
		}

		buildAST();

		graph = new AttributedGraph();
		buildGraph();

		GraphDisplay graphDisplay =
			graphDisplayBroker.getDefaultGraphDisplay(false, monitor);
//        graphDisplay.defineVertexAttribute(CODE_ATTRIBUTE); //
//        graphDisplay.defineVertexAttribute(SYMBOLS_ATTRIBUTE);
//        graphDisplay.defineEdgeAttribute(EDGE_TYPE_ATTRIBUTE);
		graphDisplay.setGraph(graph, "Data-flow AST", false, monitor);

		// Install a handler so the selection/location will map
		graphDisplay.setGraphDisplayListener(
			new ASTGraphDisplayListener(tool, graphDisplay, high, func.getProgram()));
	}

	private void buildAST() throws DecompileException {
		DecompileOptions options = new DecompileOptions();
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(options);

		if (!ifc.openProgram(this.currentProgram)) {
			throw new DecompileException("Decompiler",
				"Unable to initialize: " + ifc.getLastMessage());
		}
		ifc.setSimplificationStyle("normalize");
		DecompileResults res = ifc.decompileFunction(func, 30, null);
		high = res.getHighFunction();

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

	private String getOpKey(PcodeOpAST op) {
		SequenceNumber sq = op.getSeqnum();
		String id =
			sq.getTarget().toString(true) + " o " + Integer.toString(op.getSeqnum().getTime());
		return id;
	}

	protected AttributedVertex createVarnodeVertex(VarnodeAST vn) {
		String name = vn.getAddress().toString(true);
		String id = getVarnodeKey(vn);
		String colorattrib = "Red";
		if (vn.isConstant()) {
			colorattrib = "DarkGreen";
		}
		else if (vn.isRegister()) {
			colorattrib = "Blue";
			Register reg = func.getProgram().getRegister(vn.getAddress(), vn.getSize());
			if (reg != null) {
				name = reg.getName();
			}
		}
		else if (vn.isUnique()) {
			colorattrib = "Black";
		}
		else if (vn.isPersistant()) {
			colorattrib = "DarkOrange";
		}
		else if (vn.isAddrTied()) {
			colorattrib = "Orange";
		}
		AttributedVertex vert = graph.addVertex(id, name);
		if (vn.isInput()) {
			vert.setAttribute(ICON_ATTRIBUTE, "TriangleDown");
		}
		else {
			vert.setAttribute(ICON_ATTRIBUTE, "Circle");
		}
		vert.setAttribute(COLOR_ATTRIBUTE, colorattrib);
		return vert;
	}

	protected AttributedVertex createOpVertex(PcodeOpAST op) {
		String name = op.getMnemonic();
		String id = getOpKey(op);
		int opcode = op.getOpcode();
		if ((opcode == PcodeOp.LOAD) || (opcode == PcodeOp.STORE)) {
			Varnode vn = op.getInput(0);
			AddressSpace addrspace =
				func.getProgram().getAddressFactory().getAddressSpace((int) vn.getOffset());
			name += ' ' + addrspace.getName();
		}
		else if (opcode == PcodeOp.INDIRECT) {
			Varnode vn = op.getInput(1);
			if (vn != null) {
				PcodeOp indOp = high.getOpRef((int) vn.getOffset());
				if (indOp != null) {
					name += " (" + indOp.getMnemonic() + ')';
				}
			}
		}
		AttributedVertex vert = graph.addVertex(id, name);
		vert.setAttribute(ICON_ATTRIBUTE, "Square");
		return vert;
	}

	protected AttributedVertex getVarnodeVertex(Map<Integer, AttributedVertex> vertices, VarnodeAST vn) {
		AttributedVertex res;
		res = vertices.get(vn.getUniqueId());
		if (res == null) {
			res = createVarnodeVertex(vn);
			vertices.put(vn.getUniqueId(), res);
		}
		return res;
	}

	protected AttributedEdge createEdge(AttributedVertex in, AttributedVertex out) {
		return graph.addEdge(in, out);
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

	protected Iterator<PcodeOpAST> getPcodeOpIterator() {
		Iterator<PcodeOpAST> opiter = high.getPcodeOps();
		return opiter;
	}

	class ASTGraphDisplayListener extends AddressBasedGraphDisplayListener {

		HighFunction highfunc;

		public ASTGraphDisplayListener(PluginTool tool, GraphDisplay display, HighFunction high,
				Program program) {
			super(tool, program, display);
			highfunc = high;
		}

		@Override
		protected List<String> getVertices(AddressSetView selection) {
			List<String> ids = new ArrayList<String>();
			return ids;
		}

		@Override
		protected AddressSet getAddressSetForVertices(List<String> vertexIds) {
			AddressSet set = new AddressSet();
			for (String id : vertexIds) {
				Address address = getAddressForVertexId(id);
				if (address != null) {
					set.add(address);
				}
			}
			return set;
		}

		@Override
		protected Address getAddressForVertexId(String vertexId) {
			int firstcolon = vertexId.indexOf(':');
			if (firstcolon == -1) {
				return null;
			}

			int firstSpace = vertexId.indexOf(' ');
			String addrString = vertexId.substring(0, firstSpace);
			return getAddress(addrString);
		}
	}
}
