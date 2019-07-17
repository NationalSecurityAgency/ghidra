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
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.graph.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;

public class GraphAST extends GhidraScript {
	protected static final String COLOR_ATTRIBUTE = "Color";
	protected static final String ICON_ATTRIBUTE = "Icon";
	
	Function func;
	HighFunction high;
	GraphData graph;
	int edgecount;
	
    @Override
    public void run() throws Exception {
		PluginTool tool = state.getTool();
		if (tool == null) {
			println("Script is not running in GUI");
		}
		GraphService graphSvc = tool.getService(GraphService.class);
		if (graphSvc == null) {
			Msg.showError(this, 
					tool.getToolFrame(), 
					"GraphAST Error", 
					"GraphService not found: Please add a graph service provider to your tool");
			return;
		}
		
        func = this.getFunctionContaining(this.currentAddress);
		if (func == null) {
			Msg.showWarn(this, 
					state.getTool().getToolFrame(), 
					"GraphAST Error", 
					"No Function at current location");
			return;
		}
        
		buildAST();
		
		graph = graphSvc.createGraphContent();
		buildGraph();
		
		GraphDisplay graphDisplay = graphSvc.getGraphDisplay(true);
//        graphDisplay.defineVertexAttribute(CODE_ATTRIBUTE); //
//        graphDisplay.defineVertexAttribute(SYMBOLS_ATTRIBUTE);
//        graphDisplay.defineEdgeAttribute(EDGE_TYPE_ATTRIBUTE);
		graphDisplay.setGraphData(graph);
		
		// Install a handler so the selection/location will map
		graphDisplay.setSelectionHandler(new GraphASTSelectionHandler(graphSvc, high,func.getProgram().getAddressFactory()));
    }

   private void buildAST() throws DecompileException {
        DecompileOptions options = new DecompileOptions();
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(options);
        
		if ( !ifc.openProgram(this.currentProgram) ) {
			throw new DecompileException("Decompiler", "Unable to initialize: "+ifc.getLastMessage());
		}
		ifc.setSimplificationStyle("normalize");
		DecompileResults res = ifc.decompileFunction(func, 30, null);
        high = res.getHighFunction();
    	
    }
     
    private String getVarnodeKey(VarnodeAST vn) {
    	PcodeOp op = vn.getDef();
    	String id;
    	if (op != null)
    		id = op.getSeqnum().getTarget().toString(true) + " v " + Integer.toString(vn.getUniqueId());
    	else
    		id = "i v " + Integer.toString(vn.getUniqueId());
    	return id;
    }
    
    private String getOpKey(PcodeOpAST op) {
    	SequenceNumber sq = op.getSeqnum();
      	String id = sq.getTarget().toString(true) + " o " +Integer.toString(op.getSeqnum().getTime());
        return id; 	
    }
    
    protected GraphVertex createVarnodeVertex(VarnodeAST vn) {
    	String name = vn.getAddress().toString(true);
    	String id = getVarnodeKey(vn);
    	String colorattrib = "Red";
    	if (vn.isConstant())
    		colorattrib = "DarkGreen";
    	else if (vn.isRegister()) {
    		colorattrib = "Blue";
    		Register reg = func.getProgram().getRegister(vn.getAddress(),vn.getSize());
    		if (reg != null)
    			name = reg.getName();
    	}
    	else if (vn.isUnique())
    		colorattrib = "Black";
    	else if (vn.isPersistant())
    		colorattrib = "DarkOrange";
    	else if (vn.isAddrTied())
    		colorattrib = "Orange";
    	GraphVertex vert = graph.createVertex(name, id);
    	if (vn.isInput())
    		vert.setAttribute(ICON_ATTRIBUTE, "TriangleDown");
    	else
    		vert.setAttribute(ICON_ATTRIBUTE, "Circle");
    	vert.setAttribute(COLOR_ATTRIBUTE,colorattrib);
    	return vert;
    }
    
    protected GraphVertex createOpVertex(PcodeOpAST op) {
    	String name = op.getMnemonic();
    	String id = getOpKey(op);
    	int opcode = op.getOpcode();
    	if ((opcode==PcodeOp.LOAD)||(opcode==PcodeOp.STORE)) {
    		Varnode vn = op.getInput(0);
    		AddressSpace addrspace = func.getProgram().getAddressFactory().getAddressSpace((int)vn.getOffset());
    		name += ' ' + addrspace.getName();
    	}
    	else if (opcode == PcodeOp.INDIRECT) {
    		Varnode vn = op.getInput(1);
    		if (vn != null) {
    			PcodeOp indOp = high.getOpRef((int)vn.getOffset());
    			if (indOp != null) {
    				name += " (" + indOp.getMnemonic() +')';
    			}
    		}
    	}
    	GraphVertex vert = graph.createVertex(name, id);
    	vert.setAttribute(ICON_ATTRIBUTE, "Square");
    	return vert;
    }
    
    protected GraphVertex getVarnodeVertex(HashMap<Integer,GraphVertex> vertices,VarnodeAST vn) {
    	GraphVertex res;
    	res = vertices.get(vn.getUniqueId());
    	if (res == null) {
    		res = createVarnodeVertex(vn);
    		vertices.put(vn.getUniqueId(), res);
    	}
    	return res;
    }
    
    protected GraphEdge createEdge(GraphVertex in,GraphVertex out) {
    	String id = Integer.toString(edgecount);
    	edgecount += 1;
    	return graph.createEdge(id, in, out);
    }
    
    protected void buildGraph() {

		HashMap<Integer, GraphVertex> vertices = new HashMap<Integer, GraphVertex>();
		
		edgecount = 0;
		Iterator<PcodeOpAST> opiter = getPcodeOpIterator();
		while(opiter.hasNext()) {
			PcodeOpAST op = opiter.next();
			GraphVertex o = createOpVertex(op);
			for(int i=0;i<op.getNumInputs();++i) {
				int opcode = op.getOpcode();
				if ((i==0)&&((opcode==PcodeOp.LOAD)||(opcode==PcodeOp.STORE)))
					continue;
				if ((i==1)&&(opcode==PcodeOp.INDIRECT))
					continue;
				VarnodeAST vn = (VarnodeAST)op.getInput(i);
				if (vn != null) {
					GraphVertex v = getVarnodeVertex(vertices,vn);
					createEdge(v,o);
				}
			}
			VarnodeAST outvn = (VarnodeAST)op.getOutput();
			if (outvn != null) {
				GraphVertex outv = getVarnodeVertex(vertices,outvn);
				if (outv != null)
					createEdge(o,outv);
			}
		}
    }

	protected Iterator<PcodeOpAST> getPcodeOpIterator() {
		Iterator<PcodeOpAST> opiter = high.getPcodeOps();
		return opiter;
	}
    
    class GraphASTSelectionHandler implements GraphSelectionHandler {
    	private boolean active;   // true if the window is active
        private boolean enabled;
        HighFunction highfunc;
        private GraphService graphService;
        private AddressFactory addrFactory;

        public GraphASTSelectionHandler(GraphService graphService,HighFunction highfunc,AddressFactory addrFactory) {
        	active = false;
        	enabled = true;
        	this.graphService = graphService;
        	this.highfunc = highfunc;
        	this.addrFactory = addrFactory;
        }

        private Address keyToAddress(String key) {
        	int firstcolon = key.indexOf(':');
        	if (firstcolon == -1) return null;
        	int firstspace = key.indexOf(' ');
        	String addrspacestring = key.substring(0,firstcolon);
        	String addrstring = key.substring(firstcolon+1,firstspace);
        	AddressSpace spc = addrFactory.getAddressSpace(addrspacestring);
        	if (spc == null) return null;
        	try {
				return spc.getAddress(addrstring);
			} catch (AddressFormatException e) {
				return null;
			}
        }
        
		public String getGraphType() {
			return "Data-flow AST";
		}

		public boolean isActive() {
			return active;
		}

		public boolean isEnabled() {
			return enabled;
		}

		public void locate(String renoirLocation) {
			Address addr = keyToAddress(renoirLocation);
			if (addr==null) return;
			graphService.fireLocationEvent(addr);
		}

		public String locate(Object ghidraLocation) {
			if (!(ghidraLocation instanceof Address))
	            return null;
	        
	        Address addr = (Address)ghidraLocation;
	        Iterator<PcodeOpAST> iter = highfunc.getPcodeOps(addr);
	        if (iter.hasNext()) {
	        	PcodeOpAST op = iter.next();
	        	return getOpKey(op);
	        }
	        return null;
		}

		public boolean notify(String notificationType) {
			return false;
		}

		public void select(String[] renoirSelections) {
			if (!enabled)
	    		return;
			
			AddressSet set = new AddressSet();
			for (int i = 0; i < renoirSelections.length; i++) {
				Address addr = keyToAddress(renoirSelections[i]);
				if (addr == null) {
					continue;
				}
				set.addRange(addr,addr);
			}

			graphService.fireSelectionEvent(set);
		}

		public String[] select(Object ghidraSelection) {
			String [] keys;
			if (ghidraSelection == null) {
				keys = new String[0];
				return keys;
			}
			if (!(ghidraSelection instanceof AddressSetView)) {
				return null; // selection not understood
			}
			AddressSetView set = (AddressSetView) ghidraSelection;
			ArrayList<String> ops = new ArrayList<String>();
			Iterator<PcodeOpAST> iter = highfunc.getPcodeOps();
			while(iter.hasNext()) {
				PcodeOpAST op = iter.next();
				Address addr = op.getSeqnum().getTarget();
				if (set.contains(addr)) {
					ops.add(getOpKey(op));
					VarnodeAST vn = (VarnodeAST)op.getOutput();
					if (vn != null)
						ops.add(getVarnodeKey(vn));
				}
			}
			keys = new String[ ops.size() ];
			return ops.toArray(keys);
		}

		public void setActive(boolean active) {
			this.active = active;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}
    	
    }
}
