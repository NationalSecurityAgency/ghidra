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
package ghidra.bsfv;

import java.util.*;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.decompiler.DecompilerHighlightService;
import ghidra.app.decompiler.DecompilerHighlighter;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.*;
import ghidra.service.graph.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.table.GhidraTable;
import ghidra.util.task.TaskMonitor;

/**
 * This action is used to draw BSim feature graphs and to determine which tokens in the decompiler
 * should be highlighted for a given feature.
 */
public class HighlightAndGraphAction extends DockingAction {

	public static final String BSIM_FEATURE_HIGHLIGHTER_NAME = "BSimFeatureHighlighter";
	public static final String NAME = "Highlight and Graph";

	private BsfvTableProvider provider;
	private BSimFeatureVisualizerPlugin plugin;
	private GraphType featureGraphType;
	private GraphDisplayOptions featureGraphOptions;
	private AttributedGraph featureGraph;

	/**
	 * Creates an action for drawing BSim feature graphs and highlighting relevant tokens in the 
	 * decompiler.
	 * @param provider provider
	 * @param plugin plugin
	 */
	public HighlightAndGraphAction(BsfvTableProvider provider, BSimFeatureVisualizerPlugin plugin) {
		super(NAME, plugin.getName());
		this.provider = provider;
		this.plugin = plugin;
		featureGraphType = new BSimFeatureGraphType();
		featureGraphOptions =
			new BSimFeatureGraphDisplayOptions(featureGraphType, plugin.getTool());
		setPopupMenuData(new MenuData(new String[] { "Highlight and Graph" }));
		setDescription("Create a graph and decompiler highlight for this BSim feature");
		HelpLocation help = new HelpLocation(plugin.getName(), "Visualizing_BSim_Features");
		setHelpLocation(help);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return true;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return provider.getModel().getLastSelectedObjects().size() > 0;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GraphDisplayBroker graphDisplayBroker =
			plugin.getTool().getService(GraphDisplayBroker.class);
		if (graphDisplayBroker == null) {
			Msg.showError(this, plugin.getTool().getToolFrame(), "BSimFeatureVisualizer Error",
				"No graph display providers found: Please add a graph display provider to " +
					"your tool");
			return;
		}
		GhidraTable bsimFeatureTable = provider.getTable();
		BsfvTableModel model = provider.getModel();
		if (bsimFeatureTable.getSelectedRow() == -1) {
			return;
		}
		PcodeOpAST pcode = model.getOpAt(bsimFeatureTable.getSelectedRow());
		PcodeOpAST previousPcode = model.getPreviousOpAt(bsimFeatureTable.getSelectedRow());
		featureGraph = new AttributedGraph("BSim Feature Graph", featureGraphType);
		StringBuilder graphName = new StringBuilder();
		switch (model.getFeatureTypeAt(bsimFeatureTable.getSelectedRow())) {
			case DATA_FLOW:
				addDataFlowFeatureGraph(pcode, BSimFeatureGraphType.DATAFLOW_WINDOW_SIZE,
					featureGraph, true);
				graphName.append("DATA(");
				graphName.append(pcode.getMnemonic());
				graphName.append(")@");
				graphName.append(pcode.getSeqnum().getTarget());
				break;
			case CONTROL_FLOW:
				int blockIndex = model.getBlockIndexAt(bsimFeatureTable.getSelectedRow());
				addControlFlowFeatureGraph(blockIndex, featureGraph);
				graphName.append("CONTROL@");
				graphName.append(model.getBasicBlockStart(bsimFeatureTable.getSelectedRow()));
				break;
			case COMBINED:
				blockIndex = model.getBlockIndexAt(bsimFeatureTable.getSelectedRow());
				addControlFlowFeatureGraph(blockIndex, featureGraph);
				addDataFlowFeatureGraph(pcode, 1 + BSimFeatureGraphType.DATAFLOW_WINDOW_SIZE / 2,
					featureGraph, true);
				graphName.append("COMBINED(");
				graphName.append(pcode.getMnemonic());
				graphName.append(")@");
				graphName.append(pcode.getSeqnum().getTarget());
				break;
			case DUAL_FLOW:
				addDataFlowFeatureGraph(pcode, 1 + BSimFeatureGraphType.DATAFLOW_WINDOW_SIZE / 2,
					featureGraph, true);
				addDataFlowFeatureGraph(previousPcode,
					1 + BSimFeatureGraphType.DATAFLOW_WINDOW_SIZE / 2, featureGraph, false);
				graphName.append("DUAL(");
				graphName.append(pcode.getMnemonic());
				graphName.append(",");
				graphName.append(previousPcode.getMnemonic());
				graphName.append(")@");
				graphName.append(pcode.getSeqnum().getTarget());
				break;
			case COPY_SIG:
				blockIndex = model.getBlockIndexAt(bsimFeatureTable.getSelectedRow());
				addCopySigFeatureGraph(blockIndex, featureGraph);
				graphName.append("COPY_SIG@");
				graphName.append(model.getBasicBlockStart(bsimFeatureTable.getSelectedRow()));
				break;
			default:
				throw new IllegalArgumentException();
		}
		GraphDisplay graphDisplay = null;

		try {
			boolean reuseGraph = plugin.getReuseGraph();
			graphDisplay = graphDisplayBroker.getDefaultGraphDisplay(reuseGraph, TaskMonitor.DUMMY);
		}
		catch (GraphException e) {
			Msg.showError(this, null, "Graph Error", e.getMessage(), e);
			return;
		}

		if (graphDisplay == null) {
			Msg.showError(this, null, "null GraphDisplay", "null GraphDisplay");
		}
		else {
			try {
				//just use a dummy TaskMonitor since these graphs are small
				graphDisplay.setGraph(featureGraph, featureGraphOptions, graphName.toString(),
					false, TaskMonitor.DUMMY);
				graphDisplay.setGraphDisplayListener(new BsfvGraphDisplayListener(plugin.getTool(),
					plugin.getCurrentProgram(), graphDisplay));
			}
			catch (CancelledException e) {
				return;
			}
		}
		DecompilerHighlightService highlightService = plugin.getDecompilerHighlightService();
		if (highlightService == null) {
			Msg.showError(this, null, "DecompilerHighlightService not found",
				"DecompilerHighlightService not found");
		}
		else {
			if (!plugin.getHighlightByRow()) {
				BsfvTokenHighlightMatcher tokenMatcher = new BsfvTokenHighlightMatcher(
					model.getRowObject(bsimFeatureTable.getSelectedRow()), model.getHighFunction(),
					plugin);
				DecompilerHighlighter highlighter =
					highlightService.createHighlighter(BSIM_FEATURE_HIGHLIGHTER_NAME, tokenMatcher);
				highlighter.applyHighlights();
			}
		}

	}

	/**
	 * Returns the {@link AttributedGraph} created by (the last firing of) this action.
	 * @return graph
	 */
	AttributedGraph getGraph() {
		return featureGraph;
	}

	private void addCopySigFeatureGraph(int blockIndex, AttributedGraph graph) {
		//at the moment just graph one block
		//future improvement: search block for standalone copies and graph each one
		AttributedVertex baseBlockVertex =
			graph.addVertex(BSimFeatureGraphType.COPY_PREFIX + Integer.toString(blockIndex));
		HighFunction hfunction = provider.getModel().getHighFunction();
		PcodeBlockBasic basicBlock = hfunction.getBasicBlocks().get(blockIndex);
		setVertexTypeAndAttributes(baseBlockVertex, basicBlock,
			BSimFeatureGraphType.COPY_SIGNATURE);

	}

	private void addControlFlowFeatureGraph(Integer baseBlockIndex, AttributedGraph graph) {

		Map<Integer, AttributedVertex> indicesToVertices = new HashMap<>();
		HighFunction hfunction = provider.getModel().getHighFunction();
		ArrayList<PcodeBlockBasic> bBlocks = hfunction.getBasicBlocks();
		PcodeBlockBasic baseBlock = bBlocks.get(baseBlockIndex);
		if (baseBlock.getStart() == null || baseBlock.getStop() == null) {
			Msg.info(this, "null base block: baseBlockIndex " + baseBlockIndex);
			return;
		}

		AttributedVertex baseBlockVertex = graph.addVertex(
			BSimFeatureGraphType.CONTROL_FLOW_PREFIX + Integer.toString(baseBlockIndex));
		setVertexTypeAndAttributes(baseBlockVertex, baseBlock,
			BSimFeatureGraphType.BASE_BLOCK_VERTEX);
		indicesToVertices.put(baseBlockIndex, baseBlockVertex);

		//add the parents 
		for (int i = 0, numParents = baseBlock.getInSize(); i < numParents; i++) {
			PcodeBlock parentBlock = baseBlock.getIn(i);
			AttributedVertex parentVertex =
				indicesToVertices.computeIfAbsent(parentBlock.getIndex(),
					x -> graph.addVertex(BSimFeatureGraphType.CONTROL_FLOW_PREFIX +
						Integer.toString(parentBlock.getIndex())));
			setVertexTypeAndAttributes(parentVertex, parentBlock,
				BSimFeatureGraphType.PARENT_BLOCK_VERTEX);
			addGraphEdge(graph, parentBlock, parentVertex, baseBlock, baseBlockVertex);

			//add grandparents
			for (int j = 0, numGrandParents = parentBlock.getInSize(); j < numGrandParents; j++) {
				PcodeBlock grandParentBlock = parentBlock.getIn(j);
				AttributedVertex grandParentVertex =
					indicesToVertices.computeIfAbsent(grandParentBlock.getIndex(),
						x -> graph.addVertex(BSimFeatureGraphType.CONTROL_FLOW_PREFIX +
							Integer.toString(grandParentBlock.getIndex())));
				setVertexTypeAndAttributes(grandParentVertex, grandParentBlock,
					BSimFeatureGraphType.GRANDPARENT_BLOCK_VERTEX);
				addGraphEdge(graph, grandParentBlock, grandParentVertex, parentBlock, parentVertex);
			}
			//add the siblings 
			for (int j = 0, numSiblings = parentBlock.getOutSize(); j < numSiblings; j++) {
				PcodeBlock siblingBlock = parentBlock.getOut(j);
				if (siblingBlock.equals(baseBlock)) {
					continue;
				}
				AttributedVertex siblingVertex =
					indicesToVertices.computeIfAbsent(siblingBlock.getIndex(),
						x -> graph.addVertex(BSimFeatureGraphType.CONTROL_FLOW_PREFIX +
							Integer.toString(siblingBlock.getIndex())));
				setVertexTypeAndAttributes(siblingVertex, siblingBlock,
					BSimFeatureGraphType.SIBLING_BLOCK_VERTEX);
				addGraphEdge(graph, parentBlock, parentVertex, siblingBlock, siblingVertex);
			}
		}
		//add the children
		for (int i = 0, numChildren = baseBlock.getOutSize(); i < numChildren; i++) {
			PcodeBlock childBlock = baseBlock.getOut(i);
			AttributedVertex childVertex = indicesToVertices.computeIfAbsent(childBlock.getIndex(),
				x -> graph.addVertex(BSimFeatureGraphType.CONTROL_FLOW_PREFIX +
					Integer.toString(childBlock.getIndex())));
			setVertexTypeAndAttributes(childVertex, childBlock,
				BSimFeatureGraphType.CHILD_BLOCK_VERTEX);
			addGraphEdge(graph, baseBlock, baseBlockVertex, childBlock, childVertex);
		}
	}

	private void setVertexTypeAndAttributes(AttributedVertex vertex, PcodeBlock block,
			String vertexType) {
		String existingType = vertex.getVertexType();
		if (existingType == null) {
			vertex.setVertexType(vertexType);
		}
		else {
			if (!existingType.equals(vertexType) &&
				!existingType.equals(BSimFeatureGraphType.BASE_BLOCK_VERTEX)) {
				vertex.setVertexType(BSimFeatureGraphType.BSIM_NEIGHBOR_VERTEX);
			}
			return; //attributes already set
		}
		vertex.setAttribute(BSimFeatureGraphType.BLOCK_START, block.getStart().toString());
		vertex.setAttribute(BSimFeatureGraphType.BLOCK_STOP, block.getStop().toString());
		vertex.setAttribute(BSimFeatureGraphType.CALL_STRING,
			provider.getModel().getCallString(block.getIndex()));

	}

	private void addGraphEdge(AttributedGraph graph, PcodeBlock sourceBlock,
			AttributedVertex sourceVertex, PcodeBlock targetBlock, AttributedVertex targetVertex) {
		AttributedEdge edge = graph.addEdge(sourceVertex, targetVertex);
		if (sourceBlock.getOutSize() != 2) {
			edge.setEdgeType(BSimFeatureGraphType.CONTROL_FLOW_DEFAULT_EDGE);
			return;
		}
		//sourceBlock must end in CBRANCH, true/false edge incorporated into hash
		if (sourceBlock.getFalseOut().equals(targetBlock)) {
			edge.setEdgeType(BSimFeatureGraphType.FALSE_EDGE);
		}
		else {
			edge.setEdgeType(BSimFeatureGraphType.TRUE_EDGE);
		}
		return;
	}

	//some paths in the dataflow graph (involving chains of COPY, INDIRECT, and MULTIEQUAL ops) are
	//collapsed before signature generation.  This leads to varnodes in the dataflow graph which 
	//have defining ops but which are not base varnodes of DATA_FLOW features.  Rather than 
	///re-implement the collapsing algorithm, we just keep track of which varnodes do not have 
	//features.
	//The collapsed paths *are* shown in the BSim feature graphs created by this method, but are
	//colored to indicate that they are collapsed during feature generation
	private AttributedVertex addDataFlowFeatureGraph(PcodeOpAST pcode, int windowSize,
			AttributedGraph graph, boolean primaryBase) {
		Queue<DataflowQueueElement> varnodes = new LinkedList<>();
		VarnodeAST vn = (VarnodeAST) pcode.getOutput();

		Set<PcodeOpAST> featuredOps = provider.getModel().getFeaturedOps();
		Map<VarnodeAST, AttributedVertex> varnodesToVertices = new HashMap<>();
		Map<PcodeOpAST, AttributedVertex> opsToVertices = new HashMap<>();
		AttributedVertex baseVertex = null;
		if (vn == null) {
			baseVertex = graph.addVertex(
				BSimFeatureGraphType.DATAFLOW_PREFIX + Integer.toString(graph.getVertexCount()),
				BSimFeatureGraphType.VOID_BASE);
			vn = new VarnodeAST(Address.NO_ADDRESS, 0, 0);
		}
		else {
			baseVertex = graph.addVertex(
				BSimFeatureGraphType.DATAFLOW_PREFIX + Integer.toString(graph.getVertexCount()),
				vn.toString(plugin.getCurrentProgram().getLanguage()));
			baseVertex.setAttribute(BSimFeatureGraphType.SIZE, Integer.toString(vn.getSize()));
		}

		baseVertex.setVertexType(primaryBase ? BSimFeatureGraphType.BASE_VARNODE_VERTEX
				: BSimFeatureGraphType.SECONDARY_BASE_VARNODE_VERTEX);
		varnodesToVertices.put(vn, baseVertex);

		DataflowQueueElement base = new DataflowQueueElement(vn, windowSize);
		varnodes.add(base);

		//elements of queue should be correspond to varnodes (or artificial "base" varnode) which 
		//have a defining/corresponding pcode op
		//so no constants or function inputs in the queue (but they will be added to the *graph*)
		while (!varnodes.isEmpty()) {
			DataflowQueueElement currentElement = varnodes.poll();
			VarnodeAST outputVarnode = currentElement.vn;
			AttributedVertex varnodeVertex = varnodesToVertices.get(outputVarnode);
			PcodeOpAST currentPcode = null;
			if (outputVarnode.getAddress().equals(Address.NO_ADDRESS)) {
				//this can only happen when the pcode argument to this method has no output
				currentPcode = pcode;
			}
			else {
				currentPcode = (PcodeOpAST) outputVarnode.getDef();
			}
			//varnode vertex is collapsed if corresponding varnode is defined by a collapsed op
			//don't collapse special case where op has no output 
			boolean collapsedOp = false;
			if (!featuredOps.contains(currentPcode) && currentPcode != pcode) {
				collapsedOp = true;
			}
			if (collapsedOp) {
				varnodeVertex.setVertexType(BSimFeatureGraphType.COLLAPSED_VARNODE);
				if (opsToVertices.containsKey(currentPcode)) {
					continue; //avoid getting stuck in collapsed loop
				}
			}
			AttributedVertex pcodeVertex = opsToVertices.computeIfAbsent(currentPcode,
				x -> graph.addVertex(
					BSimFeatureGraphType.DATAFLOW_PREFIX + Integer.toString(graph.getVertexCount()),
					x.getMnemonic()));
			if (collapsedOp) {
				pcodeVertex.setVertexType(BSimFeatureGraphType.COLLAPSED_OP);
			}
			else {
				pcodeVertex.setVertexType(BSimFeatureGraphType.PCODE_OP_VERTEX);
			}
			pcodeVertex.setAttribute(BSimFeatureGraphType.OP_ADDRESS,
				currentPcode.getSeqnum().getTarget().toString());
			pcodeVertex.setAttribute(BSimFeatureGraphType.PCODE_OUTPUT,
				currentPcode.getOutput() == null ? BSimFeatureGraphType.VOID_BASE
						: currentPcode.getOutput()
								.toString(plugin.getCurrentProgram().getLanguage()));
			AttributedEdge edge = graph.addEdge(pcodeVertex, varnodeVertex);
			if (collapsedOp) {
				edge.setEdgeType(BSimFeatureGraphType.COLLAPSED_OUT);
			}
			else {
				edge.setEdgeType(BSimFeatureGraphType.DATAFLOW_OUT);
			}
			int start = 0;
			int stop = currentPcode.getNumInputs();
			switch (currentPcode.getOpcode()) {
				case PcodeOp.CPOOLREF:
					stop = 1;
					break;
				case PcodeOp.INDIRECT:
					stop -= 1;
					break;
				case PcodeOp.CALL:
				case PcodeOp.CALLIND:
				case PcodeOp.CALLOTHER:
				case PcodeOp.CBRANCH:     //should only occur with COMBINED or DUAL_FLOW features
				case PcodeOp.LOAD:
				case PcodeOp.RETURN:
				case PcodeOp.STORE:
					start += 1;
					break;
				case PcodeOp.INT_LEFT:
				case PcodeOp.INT_RIGHT:
				case PcodeOp.INT_SRIGHT:
				case PcodeOp.SUBPIECE:
					if (currentPcode.getInput(1).isConstant()) {
						stop -= 1;
					}
					break;
				default:
					break;
			}
			for (int j = start; j < stop; j++) {
				Varnode iv = currentPcode.getInput(j);
				if (iv == null) {
					Msg.info(this, "Null input for pcode " + currentPcode.getMnemonic());
					continue;
				}
				VarnodeAST inputVarnode = (VarnodeAST) iv;
				AttributedVertex inputVarnodeVertex =
					varnodesToVertices.computeIfAbsent(inputVarnode,
						x -> graph.addVertex(
							BSimFeatureGraphType.DATAFLOW_PREFIX +
								Integer.toString(graph.getVertexCount()),
							inputVarnode.toString(plugin.getCurrentProgram().getLanguage())));
				inputVarnodeVertex.setVertexType(BSimFeatureGraphType.DEFAULT_VERTEX);
				if (inputVarnode.isConstant() && inputVarnode.isInput()) {
					inputVarnodeVertex.setVertexType(BSimFeatureGraphType.CONSTANT_FUNCTION_INPUT);
				}
				else {
					if (inputVarnode.isConstant()) {
						inputVarnodeVertex.setVertexType(BSimFeatureGraphType.CONSTANT_VERTEX);
					}
					if (inputVarnode.isInput()) {
						inputVarnodeVertex.setVertexType(BSimFeatureGraphType.FUNCTION_INPUT);
					}
				}
				if (inputVarnode.isAddress()) {
					inputVarnodeVertex.setVertexType(BSimFeatureGraphType.VARNODE_ADDRESS);
				}
				inputVarnodeVertex.setAttribute(BSimFeatureGraphType.SIZE,
					Integer.toString(inputVarnode.getSize()));
				edge = graph.addEdge(inputVarnodeVertex, pcodeVertex);
				if (collapsedOp) {
					edge.setEdgeType(BSimFeatureGraphType.COLLAPSED_IN);
				}
				else {
					edge.setEdgeType(BSimFeatureGraphType.DATAFLOW_IN);
				}
				if (inputVarnode.getDef() != null) {
					int numHops = collapsedOp ? currentElement.remainingHops
							: currentElement.remainingHops - 1;
					if (numHops > 0) {
						DataflowQueueElement inputElement =
							new DataflowQueueElement(inputVarnode, numHops);
						varnodes.add(inputElement);
					}
				}
			}
		}
		return baseVertex;
	}

	private class DataflowQueueElement {
		public int remainingHops;
		public VarnodeAST vn;

		public DataflowQueueElement(VarnodeAST vn, int remainingHops) {
			this.vn = vn;
			this.remainingHops = remainingHops;
		}
	}

}
