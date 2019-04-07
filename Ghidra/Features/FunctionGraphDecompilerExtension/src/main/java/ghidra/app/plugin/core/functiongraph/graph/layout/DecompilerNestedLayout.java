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
package ghidra.app.plugin.core.functiongraph.graph.layout;

import static ghidra.program.model.pcode.PcodeBlock.*;

import java.awt.Rectangle;
import java.awt.Shape;
import java.awt.geom.Point2D;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;

import com.google.common.base.Function;

import edu.uci.ics.jung.visualization.renderers.Renderer.EdgeLabel;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.jung.renderer.DecompilerDominanceArticulatedEdgeTransformer;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.GroupedFunctionGraphVertex;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.*;
import ghidra.graph.viewer.vertex.VisualGraphVertexShapeTransformer;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

// TODO paint fallthrough differently for all, or just for those returning to the baseline
// TODO: edges for loops could stand out more...maybe not needed with better routing or background painting

// TODO: should we allow grouping in this layout?

// TODO: entry not always at the top - winhello.exe 402c8c
public class DecompilerNestedLayout extends AbstractFGLayout {

	private static final int VERTEX_TO_EDGE_ARTICULATION_OFFSET = 20;

	private DecompilerBlockGraph blockGraphRoot;

	public DecompilerNestedLayout(FunctionGraph graph) {
		this(graph, true);
	}

	private DecompilerNestedLayout(FunctionGraph graph, boolean initialize) {
		super(graph);
		if (initialize) {
			initialize();
		}
	}

	@Override
	public Function<FGEdge, Shape> getEdgeShapeTransformer() {
		return new DecompilerDominanceArticulatedEdgeTransformer();
	}

	@Override
	public EdgeLabel<FGVertex, FGEdge> getEdgeLabelRenderer() {
		return new CodeFlowEdgeLabelRenderer<>();
	}

	@Override
	protected double getCondenseFactor() {
		// our layout needs more spacing because we have custom edge routing that we want to 
		// stand out
		return .3;
	}

	@Override
	protected GridLocationMap<FGVertex, FGEdge> performInitialGridLayout(
			VisualGraph<FGVertex, FGEdge> jungGraph) throws CancelledException {

		BlockGraph outgraph = null;
		DecompileOptions decompilerOptions = new DecompileOptions();
		DecompInterface ifc = new DecompInterface();
		try {
			ifc.setOptions(decompilerOptions);

			FGVertex aVertex = jungGraph.getVertices().iterator().next();
			Program program = aVertex.getProgram();
			if (!ifc.openProgram(program)) {
				throw new RuntimeException("Unable to initialize: " + ifc.getLastMessage());
			}

			BlockGraph ingraph = buildCurrentFunctionGraph(program, jungGraph, monitor);
			if (ingraph == null) {
				throw new RuntimeException("Unable to initialize: " + ifc.getLastMessage());
			}

			outgraph = ifc.structureGraph(ingraph, program.getAddressFactory(), 0, monitor);
		}
		finally {
			ifc.dispose();
		}

		if (outgraph == null) {
			throw new RuntimeException("No results from the Decompiler: " + ifc.getLastMessage());
		}

		if (outgraph.getSize() == 0) {
			throw new RuntimeException("No results from the Decompiler: " + ifc.getLastMessage());
		}

		blockGraphRoot = new DecompilerBlockGraph(null, outgraph);

		printGraphStrucure(outgraph);
		debug("\n\n");
		printParts(0, outgraph);
		debug("\n\n");
		printConvertedStructure(0, blockGraphRoot);

		GridLocationMap<FGVertex, FGEdge> gridLocations =
			assignCoordinates(jungGraph, blockGraphRoot);

		labelEdges(jungGraph, gridLocations, blockGraphRoot);

		Address entryPoint = function.getEntryPoint();
		FGVertex vertex = getVertex(jungGraph, entryPoint);
		Integer row = gridLocations.row(vertex);
		Integer col = gridLocations.col(vertex);
		if (row != 0 || col != 0) {
			Msg.debug(this, "Function graph has entry point not at top of layout: " + entryPoint);
		}

		return gridLocations;
	}

	private void labelEdges(VisualGraph<FGVertex, FGEdge> jungGraph,
			GridLocationMap<FGVertex, FGEdge> gridLocations, DecompilerBlockGraph root) {

		Collection<FGEdge> edges = jungGraph.getEdges();
		for (FGEdge e : edges) {

			FGVertex start = e.getStart();
			FGVertex end = e.getEnd();
			Address startAddress = start.getVertexAddress();
			Address endAddress = end.getVertexAddress();
			int result = startAddress.compareTo(endAddress);
			DecompilerBlock endBlock = blockGraphRoot.getBlock(end);
			DecompilerBlock loop = endBlock.getParentLoop();
			if (result > 0 && loop != null) {
				DecompilerBlock startBlock = root.getBlock(start);
				startBlock = startBlock.parent;
				e.setLabel(startBlock.getName());
				continue;
			}

			// 
			// Special case: fallthrough--don't label this...not sure how to tell fallthrough.  For
			//               now assume that any column below or backwards is fallthrough.  However,
			//               do label fallthrough if it is the only edge.
			//
			Integer startCol = gridLocations.col(start);
			Integer endCol = gridLocations.col(end);
			boolean isFallthrough = startCol >= endCol;

			Collection<FGEdge> outEdges = jungGraph.getOutEdges(start);
			boolean hasBranching = outEdges.size() > 1;

			if (isFallthrough && hasBranching) {
				continue;
			}

			DecompilerBlock startBlock = root.getBlock(start);
			startBlock = startBlock.parent;
			e.setLabel(startBlock.getName());
		}
	}

	// TODO The	'vertexLayoutLocations' is too close to 'layoutLocations'...rename/refactor
	@Override
	protected Map<FGEdge, List<Point2D>> positionEdgeArticulationsInLayoutSpace(
			VisualGraphVertexShapeTransformer<FGVertex> transformer,
			Map<FGVertex, Point2D> vertexLayoutLocations, Collection<FGEdge> edges,
			LayoutLocationMap<FGVertex, FGEdge> layoutLocations) throws CancelledException {

		Map<FGEdge, List<Point2D>> newEdgeArticulations = new HashMap<>();

		// 
		// Route our edges!
		//
		for (FGEdge e : edges) {
			monitor.checkCanceled();

			FGVertex startVertex = e.getStart();
			FGVertex endVertex = e.getEnd();

			Address startAddress = startVertex.getVertexAddress();
			Address endAddress = endVertex.getVertexAddress();
			int result = startAddress.compareTo(endAddress);
			DecompilerBlock block = blockGraphRoot.getBlock(endVertex);
			DecompilerBlock loop = block.getParentLoop();

			if (result > 0 && loop != null) {
				// TODO better check for loops
				routeLoopEdge(vertexLayoutLocations, layoutLocations, newEdgeArticulations, e,
					startVertex, endVertex);
			}
			else {
				// 
				// TODO For now I will use the layout positions to determine edge type (nested v.
				// fallthrough). It would be nicer if I had this information defined somewhere
				// -->Maybe positioning is simple enough?
				//

				Column startCol = layoutLocations.col(startVertex);
				Column endCol = layoutLocations.col(endVertex);
				Point2D start = vertexLayoutLocations.get(startVertex);
				Point2D end = vertexLayoutLocations.get(endVertex);
				List<Point2D> articulations = new ArrayList<>();

				int direction = 20;
				if (startCol.index < endCol.index) { // going forward on the x-axis
//  TODO make constant					
//					direction = 10;
				}
				else if (startCol.index > endCol.index) { // going backwards on the x-axis
					direction = -direction;
				}

				int offsetFromVertex = isCondensedLayout()
						? (int) (VERTEX_TO_EDGE_ARTICULATION_OFFSET * (1 - getCondenseFactor()))
						: VERTEX_TO_EDGE_ARTICULATION_OFFSET;

				if (startCol.index < endCol.index) { // going left or right
					//
					// Basic routing: 
					// -leave the bottom of the start vertex
					// -first bend at some constant offset
					// -move to right or left, to above the end vertex
					// -second bend above the end vertex at previous constant offset
					//
					// Advanced considerations:
					// -Remove angles from vertex points:
					// -->Edges start/end on the vertex center.  If we offset them to avoid 
					//    overlapping, then they produce angles when only using two articulations.
					//    Thus, we will create articulations that are behind the vertices to remove
					//    the angles.  This points will not be seen.
					//
					Shape shape = transformer.apply(startVertex);
					Rectangle bounds = shape.getBounds();
					double vertexBottom = start.getY() + (bounds.height >> 1); // location is centered

					double x1 = start.getX() + direction;
					double y1 = start.getY(); // hidden
					articulations.add(new Point2D.Double(x1, y1));

					double x2 = x1;
					double y2 = vertexBottom + offsetFromVertex;
					y2 = end.getY();
					articulations.add(new Point2D.Double(x2, y2));

					double x3 = end.getX() + (-direction);
					double y3 = y2;
					articulations.add(new Point2D.Double(x3, y3));

//					double x4 = x3;
//					double y4 = end.getY(); // hidden
//					articulations.add(new Point2D.Double(x4, y4));
				}

				else if (startCol.index > endCol.index) { // flow return
					e.setAlpha(.25);

					Shape shape = transformer.apply(startVertex);
					Rectangle bounds = shape.getBounds();
					double vertexBottom = start.getY() + (bounds.height >> 1); // location is centered

					double x1 = start.getX() + (direction);
					double y1 = start.getY(); // hidden
					articulations.add(new Point2D.Double(x1, y1));

					double x2 = x1;
					double y2 = vertexBottom + offsetFromVertex;
					articulations.add(new Point2D.Double(x2, y2));

					double x3 = end.getX() + (-direction);
					double y3 = y2;
					articulations.add(new Point2D.Double(x3, y3));

					double x4 = x3;
					double y4 = end.getY(); // hidden
					articulations.add(new Point2D.Double(x4, y4));
				}

				else {  // same column--nothing to route
					// straight line, which is the default
					e.setAlpha(.25);
				}
				newEdgeArticulations.put(e, articulations);
			}
		}

		return newEdgeArticulations;
	}

	private void routeLoopEdge(Map<FGVertex, Point2D> vertexLayoutLocations,
			LayoutLocationMap<FGVertex, FGEdge> layoutLocations,
			Map<FGEdge, List<Point2D>> newEdgeArticulations, FGEdge e, FGVertex startVertex,
			FGVertex endVertex) {
		// going backwards
		List<Point2D> articulations = new ArrayList<>();

		DecompilerBlock block = blockGraphRoot.getBlock(endVertex);
		DecompilerBlock loop = block.getParentLoop();
		Set<FGVertex> vertices = loop.getVertices();

		// loop first point - same y coord as the vertex; x is the middle of the next col
		Column outermostCol = getOutermostCol(layoutLocations, vertices);
		Column afterColumn = layoutLocations.nextColumn(outermostCol);

		int halfWidth = afterColumn.getPaddedWidth(isCondensedLayout()) >> 1;
		double x = afterColumn.x + halfWidth; // middle of the column

		Point2D startVertexPoint = vertexLayoutLocations.get(startVertex);

		double y1 = startVertexPoint.getY();
		Point2D first = new Point2D.Double(x, y1);
		articulations.add(first);

		// loop second point - same y coord as destination; 
		// 					   x is the col after the outermost dominated vertex

		Point2D endVertexPoint = vertexLayoutLocations.get(endVertex);
		double y2 = endVertexPoint.getY();
		Point2D second = new Point2D.Double(x, y2);
		articulations.add(second);

		newEdgeArticulations.put(e, articulations);
	}

	private Column getOutermostCol(LayoutLocationMap<FGVertex, FGEdge> layoutLocations,
			Set<FGVertex> vertices) {

		Column outermost = null;
		for (FGVertex v : vertices) {
			Column col = layoutLocations.col(v);
			if (outermost == null) {
				outermost = col;
			}
			else if (col.x > outermost.x) {
				outermost = col;
			}
		}

		return outermost;
	}

	@Override
	public boolean usesEdgeArticulations() {
		return true;
	}

	@Override
	protected Point2D getVertexLocation(FGVertex v, Column col, Row<FGVertex> row,
			Rectangle bounds) {
		return getCenteredVertexLocation(v, col, row, bounds);
	}

	private void debug(String text) {
//		System.err.println(text);
	}

	private void printParts(int depth, BlockGraph block) {
		int blockSize = block.getSize();

		debug(printDepth(0, depth) + PcodeBlock.typeToName(block.getType()) + "  - (" +
			block.getStart() + "->" + block.getStop() + ") ");

		for (int i = 0; i < blockSize; i++) {
			PcodeBlock child = block.getBlock(i);
			StringBuilder buffy = new StringBuilder();
			buffy.append(printDepth(1, depth + 1)).append(' ').append(child);

			debug(buffy.toString());
		}

		for (int i = 0; i < blockSize; i++) {
			PcodeBlock child = block.getBlock(i);
			if (child instanceof BlockGraph) {
				printParts(depth + 1, (BlockGraph) child);
				continue;
			}
		}
	}

	private void printConvertedStructure(int depth, DecompilerBlockGraph blockGraph) {
		String depthString = printDepth(depth, depth);

		String blockName = blockGraph.getName();
		if (blockName != null) {
			debug(depthString + blockName);

			String childrenString = blockGraph.getChildrenString(depth + 1);
			if (!childrenString.isEmpty()) {
				debug(childrenString);
			}
		}

		List<DecompilerBlock> list = blockGraph.allChildren;
		for (DecompilerBlock block : list) {
			if (block instanceof DecompilerBlockGraph) {
				printConvertedStructure(depth + 1, (DecompilerBlockGraph) block);
			}
			else {
				debug(depthString + "::" + block.getName());
			}
		}
	}

	private void printGraphStrucure(BlockGraph blockGraph) {
		printBlock(new AtomicInteger(0), 0, blockGraph);
	}

	private void printBlock(AtomicInteger parentID, int depth, BlockGraph block) {
		debug(parentID + " " + printDepth(depth, depth) + +(parentID.get() - 1) + " " +
			PcodeBlock.typeToName(block.getType()) + "  - (" + block.getStart() + "->" +
			block.getStop() + ") ");

		int blockSize = block.getSize();
		int ID = parentID.getAndIncrement();

		for (int i = 0; i < blockSize; i++) {
			PcodeBlock child = block.getBlock(i);
			if (child instanceof BlockGraph) {
				printBlock(parentID, depth + 1, (BlockGraph) child);
				continue;
			}

			BlockCopy copy = (BlockCopy) child;

			StringBuilder buffy = new StringBuilder();
			buffy.append(printDepth(depth, depth + 1)).append(' ').append(ID).append(
				" plain - ").append(copy.getRef());

			debug(buffy.toString());
		}
	}

	private String printDepth(int level, int depth) {
		if (depth == 0) {
			return "";
		}

		StringBuilder buffy = new StringBuilder();
		for (int i = 0; i < depth * 2; i++) {
			buffy.append(' ');
		}

		buffy.append(' ');
		return buffy.toString();
	}

	private GridLocationMap<FGVertex, FGEdge> assignCoordinates(
			VisualGraph<FGVertex, FGEdge> jungGraph, DecompilerBlockGraph root) {
		GridLocationMap<FGVertex, FGEdge> gridLocations = new GridLocationMap<>();

		root.setCol(0);  // recursive
		debug("\n\n");
		root.setRows(0); // recursive

		Collection<FGVertex> vertices = jungGraph.getVertices();
		for (FGVertex vertex : vertices) {
			DecompilerBlock block = root.getBlock(vertex);
			int col = block.getCol();
			int row = block.getRow();
			gridLocations.set(vertex, row, col);
		}

		return gridLocations;
	}

	private FGVertex getVertex(VisualGraph<FGVertex, FGEdge> jungGraph, Address address) {
		Collection<FGVertex> vertices = jungGraph.getVertices();
		for (FGVertex v : vertices) {
			if (v.containsAddress(address)) {
				return v;
			}
		}

		// this is unusual; can happen if the program is being changed while this is running
		// throw new AssertException("Cannot find vertex for address: " + address);
		Msg.debug(this, "Unable to find vertex for address; has the program changed?: " + address);
		return null;
	}

	private BlockGraph buildCurrentFunctionGraph(Program program,
			VisualGraph<FGVertex, FGEdge> jungGraph, TaskMonitor taskMonitor)
			throws CancelledException {

		CodeBlockModel blockModel = new BasicBlockModel(program);
		AddressSetView addresses = function.getBody();
		CodeBlockIterator iterator = blockModel.getCodeBlocksContaining(addresses, taskMonitor);

		BlockGraph blockGraph = new BlockGraph();
		BidiMap<CodeBlock, PcodeBlock> bidiMap = new DualHashBidiMap<>();
		for (; iterator.hasNext();) {
			taskMonitor.checkCanceled();

			CodeBlock codeBlock = iterator.next();
			FGVertex vertex = getVertex(jungGraph, codeBlock.getMinAddress());
			if (vertex == null) {
				// this is unusual; can happen if the program is being changed while this is running
				continue;
			}

			PcodeBlock pcodeBlock = new BlockCopy(vertex, codeBlock.getMinAddress());
			bidiMap.put(codeBlock, pcodeBlock);
			blockGraph.addBlock(pcodeBlock);
		}

		for (CodeBlock block : bidiMap.keySet()) {
			taskMonitor.checkCanceled();

			CodeBlockReferenceIterator destinations = block.getDestinations(taskMonitor);
			while (destinations.hasNext()) {
				taskMonitor.checkCanceled();

				CodeBlockReference ref = destinations.next();
				// We only want control flow that is internal to the function. Make sure to
				// exclude the case where a function contains a (recursive) call to itself:
				// The reference would be between addresses internal to the function, but the
				// link doesn't represent internal flow. So we filter out ANY call reference.
				if (ref.getFlowType().isCall()) {
					continue;
				}
				CodeBlock destination = ref.getDestinationBlock();

				PcodeBlock sourcePcodeBlock = bidiMap.get(block);
				PcodeBlock destPcodeBlock = bidiMap.get(destination);
				if (destPcodeBlock == null) {
					continue;
				}

				blockGraph.addEdge(sourcePcodeBlock, destPcodeBlock);
			}
		}

		blockGraph.setIndices();
		return blockGraph;
	}

	@Override
	protected AbstractVisualGraphLayout<FGVertex, FGEdge> createClonedFGLayout(
			FunctionGraph newGraph) {
		return new DecompilerNestedLayout(newGraph, false);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class DecompilerBlockGraph extends DecompilerBlock {

		protected List<DecompilerBlock> allChildren = new ArrayList<>();

		DecompilerBlockGraph(DecompilerBlockGraph parent, BlockGraph blockGraph) {
			super(parent, blockGraph);

			int childCount = blockGraph.getSize();
			for (int i = 0; i < childCount; i++) {
				PcodeBlock block = blockGraph.getBlock(i);
				if (block instanceof BlockGraph) {
					DecompilerBlockGraph decompilerBlock =
						getDecompilerBlock(this, (BlockGraph) block);
					allChildren.add(decompilerBlock);
				}

				if (block instanceof BlockCopy) {
					DecompilerCopy decompilerCopy = new DecompilerCopy(this, (BlockCopy) block);
					allChildren.add(decompilerCopy);
				}
			}
		}

		@Override
		DecompilerBlock getBlock(FGVertex vertex) {
			for (DecompilerBlock child : allChildren) {
				DecompilerBlock block = child.getBlock(vertex);
				if (block != null) {
					return block;
				}
			}

			return null;
		}

		@Override
		DecompilerBlock getParentLoop() {
			if (parent == null) {
				return null;
			}
			return parent.getParentLoop();
		}

		@Override
		Set<FGVertex> getVertices() {
			Set<FGVertex> set = new HashSet<>();
			for (DecompilerBlock child : allChildren) {
				set.addAll(child.getVertices());
			}
			return set;
		}

		@Override
		void setCol(int col) {

			//
			// The *default* structure for children's nesting:
			// -the first node is always at the root nesting level
			// -all other children are indented by 1
			//
			for (int i = 0; i < allChildren.size(); i++) {
				int column = (i == 0) ? col : col + 1;
				DecompilerBlock block = allChildren.get(i);
				block.setCol(column);
			}

			doSetCol(col);
		}

		protected void doSetCol(int col) {
			super.setCol(col);
		}

		int setRows(int startRow) {

			int row = startRow;

			for (int i = 0; i < allChildren.size(); i++) {
				DecompilerBlock block = allChildren.get(i);
				if (block instanceof DecompilerBlockGraph) {
					row = ((DecompilerBlockGraph) block).setRows(row);
				}
				else {
					block.setRow(row++);
				}
			}

			return row;
		}

		@Override
		String getName() {
			return null;
//			return "Block";  TODO could put in a 'debug name' method for debugging
		}

		@Override
		String getChildrenString(int depth) {
			StringBuilder buffy = new StringBuilder();
			int childCount = 0;
			for (int i = 0; i < allChildren.size(); i++) {
				DecompilerBlock block = allChildren.get(i);
				if (block instanceof DecompilerBlockGraph) {

					String blockName = block.getName();
					if (blockName != null) {
						childCount++;

						if (childCount > 1) {
							buffy.append('\n');
						}
						buffy.append(printDepth(depth, depth));
//						buffy.append(childCount).append(' ');
						buffy.append(' ');
						buffy.append(blockName);
					}

				}
			}

			return buffy.toString();
		}
	}

	private abstract class DecompilerBlock {
		protected DecompilerBlock parent;
		protected PcodeBlock pcodeBlock;
		private int row;
		private int col;

		DecompilerBlock(DecompilerBlock parent, PcodeBlock pcodeBlock) {
			this.parent = parent;
			this.pcodeBlock = pcodeBlock;
		}

		void setRow(int row) {
			this.row = row;
		}

		void setCol(int col) {
			this.col = col;
		}

		int getRow() {
			return row;
		}

		int getCol() {
			return col;
		}

		abstract DecompilerBlock getBlock(FGVertex vertex);

		abstract Set<FGVertex> getVertices();

		abstract DecompilerBlock getParentLoop();

		abstract String getName();

		abstract String getChildrenString(int depth);

		@Override
		public String toString() {
			return PcodeBlock.typeToName(pcodeBlock.getType()) + " - " + pcodeBlock.getStart();
		}
	}

	private class DecompilerCopy extends DecompilerBlock {
		private BlockCopy copy;
		private Set<FGVertex> vertexSet = new HashSet<>();

		DecompilerCopy(DecompilerBlockGraph parent, BlockCopy copy) {
			super(parent, copy);
			this.copy = copy;
			vertexSet.add((FGVertex) copy.getRef());
			vertexSet = Collections.unmodifiableSet(vertexSet);
		}

		FGVertex getVertex() {
			return (FGVertex) copy.getRef();
		}

		@Override
		DecompilerBlock getBlock(FGVertex vertex) {
			//
			// Note: we currently allow grouping in this layout.  When we search for a vertex, 
			//       we have to check each vertex inside of the given group *and* each vertex 
			//       inside of the vertex that belongs to this decompiler block.
			//
			if (vertex instanceof GroupedFunctionGraphVertex) {
				Set<FGVertex> vertices = ((GroupedFunctionGraphVertex) vertex).getVertices();
				for (FGVertex collapsedVertex : vertices) {
					// note: the group may itself contain other groups--it's recursive
					DecompilerBlock block = getBlock(collapsedVertex);
					if (block != null) {
						return block;
					}
				}
			}

			FGVertex myVertex = getVertex();
			DecompilerBlock block = compareToMyVertex(myVertex, vertex);
			return block;
		}

		private DecompilerBlock compareToMyVertex(FGVertex myVertex, FGVertex vertex) {
			if (myVertex instanceof GroupedFunctionGraphVertex) {
				Set<FGVertex> vertices = ((GroupedFunctionGraphVertex) myVertex).getVertices();
				for (FGVertex myCollapsedVertex : vertices) {
					DecompilerBlock block = compareToMyVertex(myCollapsedVertex, vertex);
					if (block != null) {
						return block;
					}
				}
			}

			if (myVertex.equals(vertex)) {
				return this;
			}
			return null;
		}

		@Override
		DecompilerBlock getParentLoop() {
			return parent.getParentLoop();
		}

		@Override
		Set<FGVertex> getVertices() {
			return vertexSet;
		}

		@Override
		String getName() {
			return "Copy"; // we don't usually want to see this
		}

		@Override
		String getChildrenString(int depth) {
			return null;
		}
	}

	private DecompilerBlockGraph getDecompilerBlock(DecompilerBlockGraph parent, BlockGraph block) {

		switch (block.getType()) {
			case PLAIN:
				return new DecompilerBlockGraph(parent, block);
			case BASIC:
				return new DecompilerBlockGraph(parent, block);
			case GRAPH:
				return new DecompilerBlockGraph(parent, block);
			case COPY:
				return new PlainBlock(parent, block);
			case GOTO:
				return new DecompilerBlockGraph(parent, block);
			case MULTIGOTO:
				return new DecompilerBlockGraph(parent, block);
			case LIST:
				return new ListBlock(parent, block);
			case CONDITION:
				return new ConditionBlock(parent, block); // TODO - not sure
			case PROPERIF:
				return new IfBlock(parent, block);
			case IFELSE:
				return new IfElseBlock(parent, block);
			case IFGOTO:
				return new IfBlock(parent, block); // TODO - not sure
			case WHILEDO:
				return new WhileLoopBlock(parent, block);
			case DOWHILE:
				return new DoLoopBlock(parent, block);
			case SWITCH:
				return new SwitchBlock(parent, block);
			case INFLOOP:
				return new DecompilerBlockGraph(parent, block);
		}

		throw new AssertException(
			"Unhandled Decompiler Type: " + PcodeBlock.typeToName(block.getType()));
	}

	private abstract class DecompilerLoop extends DecompilerBlockGraph {

		DecompilerLoop(DecompilerBlockGraph parent, BlockGraph block) {
			super(parent, block);
		}

		@Override
		DecompilerBlock getParentLoop() {
			return this;
		}
	}

	private class PlainBlock extends DecompilerBlockGraph {
		PlainBlock(DecompilerBlockGraph parent, BlockGraph block) {
			super(parent, block);
		}

		@Override
		String getName() {
			return "Plain";  // TODO: maybe just null
		}
	}

	private class ListBlock extends DecompilerBlockGraph {
		ListBlock(DecompilerBlockGraph parent, BlockGraph block) {
			super(parent, block);
		}

		@Override
		void setCol(int col) {

			//
			// The 'list' structure for children's nesting:
			// -all nodes are at the same level
			//
			for (int i = 0; i < allChildren.size(); i++) {
				int column = col;
				DecompilerBlock block = allChildren.get(i);
				block.setCol(column);
			}

			doSetCol(col);
		}

		@Override
		String getName() {
			return parent.getName();
//			return "List";
		}
	}

	private class ConditionBlock extends DecompilerBlockGraph {

		ConditionBlock(DecompilerBlockGraph parent, BlockGraph blockGraph) {
			super(parent, blockGraph);
		}

		@Override
		void setCol(int col) {

			//
			// The 'condition' structure for children's nesting:
			// -the first condition is at the base index
			// -each successive condition is another level nested
			//
			int column = col;
			for (int i = 0; i < allChildren.size(); i++) {
				DecompilerBlock block = allChildren.get(i);
				block.setCol(column);
				column++;
			}

			doSetCol(col);
		}

		@Override
		String getName() {
			return "Condition";
		}
	}

	private class WhileLoopBlock extends DecompilerLoop {

		WhileLoopBlock(DecompilerBlockGraph parent, BlockGraph blockGraph) {
			super(parent, blockGraph);
		}

		@Override
		String getName() {
			return "While Loop";
		}
	}

	private class DoLoopBlock extends DecompilerLoop {

		DoLoopBlock(DecompilerBlockGraph parent, BlockGraph blockGraph) {
			super(parent, blockGraph);
		}

		@Override
		void setCol(int col) {

			//
			// The 'do' structure for children's nesting:
			// -all blocks nested 
			//
			int column = col + 1;
			for (int i = 0; i < allChildren.size(); i++) {
				DecompilerBlock block = allChildren.get(i);
				block.setCol(column);
			}

			doSetCol(col);  // TODO does the non-copy block need a column??
		}

		@Override
		String getName() {
			return "Do Loop";
		}
	}

	private class IfBlock extends DecompilerBlockGraph {

		IfBlock(DecompilerBlockGraph parent, BlockGraph blockGraph) {
			super(parent, blockGraph);
		}

		@Override
		String getName() {
			return "If";
		}
	}

	private class IfElseBlock extends DecompilerBlockGraph {

		IfElseBlock(DecompilerBlockGraph parent, BlockGraph blockGraph) {
			super(parent, blockGraph);
		}

		@Override
		String getName() {
			return "If / Else";
		}
	}

	private class SwitchBlock extends DecompilerBlockGraph {

		SwitchBlock(DecompilerBlockGraph parent, BlockGraph blockGraph) {
			super(parent, blockGraph);
		}

		@Override
		String getName() {
			return "Switch";
		}
	}

}
