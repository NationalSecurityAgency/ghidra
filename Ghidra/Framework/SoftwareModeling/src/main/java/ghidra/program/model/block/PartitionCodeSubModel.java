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
package ghidra.program.model.block;

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NoValueException;
import ghidra.util.graph.*;
import ghidra.util.graph.attributes.AttributeManager;
import ghidra.util.graph.attributes.IntegerAttribute;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * <CODE>PartitionCodeSubModel</CODE> (Model-P) defines subroutines which do not share code with
 * other subroutines and may have one or more entry points.
 * Entry points represent anyone of a variety of flow entries, including a source, called, jump or
 * fall-through entry point.
 * <P>
 * MODEL-P is the answer to those who always want to be able to know what subroutine
 * a given instruction is in, but also do not want the subroutine to have multiple
 * entry points.  When a model-M subroutine has multiple entry points,
 * that set of code will necessarily consist of several model-P subroutines.  When
 * a model-M subroutine has a single entry point, it will consist of a single model-P subroutine
 * which has the same address set and entry point.
 *
 * @see ghidra.program.model.block.CodeBlockModel
 *
 * 
 *
 * Created February 7, 2002.
 */
public class PartitionCodeSubModel implements SubroutineBlockModel {

	public static final String NAME = "Partitioned Code";

	private Program program;
	private Listing listing;
	private CodeBlockCache foundModelP;     // cache for model-P subroutine
	private MultEntSubModel modelM;

	private final static CodeBlock[] emptyArray = new CodeBlock[0];

	// create graph and the vertex attributes associated with the graph
	private final static String ENTRY_POINT_TAG = "Entry Point Tag";
	private final static String SOURCE_NUMBER = "Source Number";
	private String attributeType = AttributeManager.INTEGER_TYPE;

	private DirectedGraph g;
	private AttributeManager<?> vertexAttributes;
	private IntegerAttribute<Vertex> entAttribute;

	/**
	 *  Construct a Model-P subroutine on a program.
	 *
	 * @param program program to create blocks from.
	 */
	public PartitionCodeSubModel(Program program) {
		this(program, false);
	}

	/**
	 *  Construct a Model-P subroutine on a program.
	 *
	 * @param program program to create blocks from.
	 * @param includeExternals externals included if true
	 */
	public PartitionCodeSubModel(Program program, boolean includeExternals) {
		this.program = program;
		listing = program.getListing();
		foundModelP = new CodeBlockCache();
		modelM = new MultEntSubModel(program, includeExternals);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#getCodeBlockAt(ghidra.program.model.address.Address, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public CodeBlock getCodeBlockAt(Address addr, TaskMonitor monitor) throws CancelledException {

		// First check out the Block cache
		CodeBlock block = foundModelP.getBlockAt(addr);
		if (block != null) {
			return block;
		}

		// get block containing addr, but return it only if it's entry point is addr
		block = getFirstCodeBlockContaining(addr, monitor);
		if (block != null) {
			if (block.getFirstStartAddress().equals(addr)) {
				return block;
			}
		}
		return null;
	}

	/**
	 * Get all the Code Blocks containing the address.
	 * For model-P, there is only one.
	 *
	 * @param addr   Address to find a containing block.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @return A CodeBlock array with one entry containing the subroutine that
	 *              contains the address null otherwise.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@Override
	public CodeBlock[] getCodeBlocksContaining(Address addr, TaskMonitor monitor)
			throws CancelledException {

		CodeBlock[] blocks = new CodeBlock[1];

		// First check out the Block cache
		blocks[0] = foundModelP.getFirstBlockContaining(addr);
		if (blocks[0] != null) {
			return blocks;
		}

		/* Get Model-M subroutine that contains addr.  If only one
		entry point, then return it in blocks[0].  If multiple
		entry points, need to find all model-P subroutines and return
		the one that contains addr in blocks[0] */
		CodeBlock modelMSub = modelM.getFirstCodeBlockContaining(addr, monitor);
		if (modelMSub == null) {
			return emptyArray;
		}
		Address[] entPts = modelMSub.getStartAddresses();
		AddressSet modelMSet = new AddressSet(modelMSub);
		if (entPts.length == 1) { // if one entry point ...
			// make this a model-P subroutine
			blocks[0] = createSub(modelMSet, entPts[0]);
			return blocks;
		}
		/* get all model-P code blocks that are contained in the
		                model-M code block and return the one containing addr */
		CodeBlock[] subs = getModelPSubs(modelMSub, monitor);
		for (CodeBlock sub : subs) {
			if (sub.contains(addr)) {
				blocks[0] = sub;
				return blocks;
			}
		}
		return emptyArray;
	}

	/**
	 * Get the (first) Model-P subroutine that contains the address.
	 * This is equivalent to getCodeBlocksContaining(addr) except that
	 * it doesn't return an array since model-P subroutines don't share code.
	 *
	 * @param addr   Address to find a containing block.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @return A CodeBlock if any block contains the address.
	 *         empty array otherwise.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@Override
	public CodeBlock getFirstCodeBlockContaining(Address addr, TaskMonitor monitor)
			throws CancelledException {
		CodeBlock[] blocks = getCodeBlocksContaining(addr, monitor);
		if (blocks.length != 0) {
			return blocks[0];
		}
		return null;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#getCodeBlocks(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public CodeBlockIterator getCodeBlocks(TaskMonitor monitor) {
		return new PartitionCodeSubIterator(this, monitor);
	}

	/**
	 * Get an iterator over CodeBlocks which overlap the specified address set.
	 *
	 * @param addrSet   an address set within program
	 * @param monitor task monitor which allows user to cancel operation.
	 */
	@Override
	public CodeBlockIterator getCodeBlocksContaining(AddressSetView addrSet, TaskMonitor monitor) {
		return new PartitionCodeSubIterator(this, addrSet, monitor);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#getProgram()
	 */
	@Override
	public Program getProgram() {
		return program;
	}

	/**
	 * Returns the listing associated with this block model.
	 * @return the listing associated with this block model
	 */
	public Listing getListing() {
		return listing;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#getName(ghidra.program.model.block.CodeBlock)
	 */
	@Override
	public String getName(CodeBlock block) {

		if (!(block.getModel() instanceof PartitionCodeSubModel)) {
			throw new IllegalArgumentException();
		}

		// get the start address for the block
		// look up the symbol in the symbol table.
		// it should have one if anyone calls it.
		// if not, make up a label

		Address start = block.getFirstStartAddress();

		Symbol symbol = program.getSymbolTable().getPrimarySymbol(start);
		if (symbol != null) {
			return symbol.getName();
		}

		// Check for fall-through condition
		Instruction inst = getListing().getInstructionBefore(start);
		if (inst != null) {
			Address a = inst.getFallThrough();
			if (start.equals(a)) {
				// ?? Naming conflicts with dynamic symbol naming
				return "SUB" + start;
			}
		}

		// This must be a source
		return "SOURCE_SUB" + start.toString();
	}

	/**
	 * Return in general how things flow out of this node.
	 * This method exists for the SIMPLEBLOCK model.
	 *
	 * <p>
	 * Since it doesn't make a great deal of sense to ask for this method
	 * in the case of subroutines, we return FlowType.UNKNOWN
	 * as long as the block exists.</p>
	 *
	 * <p>
	 * If this block has no valid instructions, it can't flow,
	 * so FlowType.INVALID is returned.</p>
	 *
	 * @return flow type of this node
	 */
	@Override
	public FlowType getFlowType(CodeBlock block) {

		if (!(block.getModel() instanceof PartitionCodeSubModel)) {
			throw new IllegalArgumentException();
		}

		/* If there are multiple unique ways out of the node, then we
		    should return FlowType.UNKNOWN (or FlowType.MULTIFLOW ?).
		   Possible considerations for the future which are particularly
		    applicable to model-P subroutines: add FlowType.MULTICALL if
		    only calls out and FlowType.MULTIJUMP if multiple jumps OUT
		    (as opposed to jumping within the subroutine).
		    Might want to consider FlowType.MULTITERMINAL for multiple returns? */

		// Determine if block is terminal
		try {
			CodeBlockReferenceIterator iter =
				new SubroutineDestReferenceIterator(block, TaskMonitorAdapter.DUMMY_MONITOR);
			while (iter.hasNext()) {
				if (!iter.next().getFlowType().isCall()) {
					return RefType.FLOW;
				}
			}
		}
		catch (CancelledException e) {
			// can't happen; dummy monitor
		}
		return RefType.TERMINATOR;
	}

	/**
	 *  Get an iterator over source blocks flowing into this block.
	 *
	 * @param block code block to get the source iterator for.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@Override
	public CodeBlockReferenceIterator getSources(CodeBlock block, TaskMonitor monitor)
			throws CancelledException {

		if (!(block.getModel() instanceof PartitionCodeSubModel)) {
			throw new IllegalArgumentException();
		}

		return new SubroutineSourceReferenceIterator(block, monitor);
	}

	/**
	 * Get number of block source references flowing into this block.
	 *
	 * @param block code block to get the source iterator for.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@Override
	public int getNumSources(CodeBlock block, TaskMonitor monitor) throws CancelledException {

		if (!(block.getModel() instanceof PartitionCodeSubModel)) {
			throw new IllegalArgumentException();
		}

		return SubroutineSourceReferenceIterator.getNumSources(block, monitor);
	}

	/**
	 *  Get an iterator over destination blocks flowing from this block.
	 *
	 * @param block code block to get the destination block iterator for.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@Override
	public CodeBlockReferenceIterator getDestinations(CodeBlock block, TaskMonitor monitor)
			throws CancelledException {

		if (!(block.getModel() instanceof PartitionCodeSubModel)) {
			throw new IllegalArgumentException();
		}

		return new SubroutineDestReferenceIterator(block, monitor);
	}

	/**
	 * Get number of destination references flowing out of this subroutine (block).
	 * All Calls from this block, and all external FlowType block references
	 * from this block are counted.
	 * 
	 * @param block code block to get the number of destination references from.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@Override
	public int getNumDestinations(CodeBlock block, TaskMonitor monitor) throws CancelledException {

		if (!(block.getModel() instanceof PartitionCodeSubModel)) {
			throw new IllegalArgumentException();
		}

		return SubroutineDestReferenceIterator.getNumDestinations(block, monitor);
	}

	/**
	 *  Compute an address set that represents all the addresses contained
	 *  in all instructions that are part of this block
	 *
	 * @param block code block to compute address set for.
	 */
//    public AddressSetView getAddressSet(CodeBlock block) {
//
//        if (!(block.getModel() instanceof PartitionCodeSubModel))
//            throw new IllegalArgumentException();
//
//        return new AddressSet((AddressSetView) block);
//    }

	/**
	 * Create a new Subroutine which has an address set and entry point.
	 * @param  set the address set contained within the subroutine/block.
	 * @param  entryPt the entry point address.
	 * @return subroutine that was created
	 */
	private CodeBlock createSub(AddressSetView set, Address entryPt) {

		CodeBlock sub = foundModelP.getBlockAt(entryPt);
		if (sub != null) {
// ?? May need to check if they have same AddressSet and entry points
			return sub;
		}

		Address[] starts = new Address[1];
		starts[0] = entryPt;
		sub = new CodeBlockImpl(this, starts, set);
		foundModelP.addObject(sub, set);
		return sub;
	}

	/**
	 * Generate a graph of a Model-M subroutine.  This graph will facilitate the
	 * Model-P algorythm as performed in the partitionGraph() method.
	 *
	 * @param modelMSub a valid Model-M subroutine block.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@SuppressWarnings("unchecked")
	private void createBlockGraph(CodeBlock modelMSub, TaskMonitor monitor)
			throws CancelledException {

		g = new DirectedGraph();
		vertexAttributes = g.vertexAttributes();
		entAttribute = (IntegerAttribute<Vertex>) vertexAttributes.createAttribute(ENTRY_POINT_TAG,
			attributeType);

		Vertex fromVertex, targetVertex;
		Address targetAddr;

		// make list of entry points
		Address[] entPts = modelMSub.getStartAddresses();
		LinkedList<Address> entryAddrList = new LinkedList<>();
		for (Address entPt : entPts) {
			entryAddrList.addLast(entPt);
		}

		// get the simple blocks contained in the model-M subroutine
		CodeBlockModel blockModel = modelM.getBasicBlockModel();
		CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(modelMSub, monitor);

		// iterate over the blocks
		while (blockIter.hasNext()) {

			CodeBlock block = blockIter.next();

			// Get or create vertex (reuse a vertex if previously created for this block)
			Vertex[] verticesOfBlock = g.getVerticesHavingReferent(block);
			fromVertex = (verticesOfBlock.length != 0) ? verticesOfBlock[0] : new Vertex(block);

			// add vertex to graph and set entry point attribute if it's associated with an entry point
			g.add(fromVertex);
			Address[] entryPts = block.getStartAddresses();
			for (int i = 0; i < entryPts.length; i++) {
				if (entryAddrList.contains(entryPts[i])) {
					entAttribute.setValue(fromVertex, i); // tag block with entry point index offset
					break;
				}
			}

			// connect children of fromVertex
			CodeBlockReferenceIterator destinations = block.getDestinations(monitor);
			while (destinations.hasNext()) {
				CodeBlockReference destinationReference = destinations.next();

				// we don't want to flow out of fromVertex if call or terminal flow type
				//  This is unnecessary if calls don't end blocks in the simple block model
				//  But, since some implementations of block models allow for this, it's better
				//  to be safe than sorry!
				FlowType flowType = destinationReference.getFlowType(); // flow type from fromVertex to child
				if (flowType.isCall() || flowType.isTerminal()) {
					continue;
				}

				targetAddr = destinationReference.getDestinationAddress();
				CodeBlock targetBlock = blockModel.getFirstCodeBlockContaining(targetAddr, monitor);
				if (targetBlock != null) {
					entryPts = targetBlock.getStartAddresses();
					boolean connect = true;
					for (Address entryPt : entryPts) {
						if (entryAddrList.contains(entryPt)) { // don't connect to an existing entry point
							connect = false;
						}
					}
					if (connect) {
						verticesOfBlock = g.getVerticesHavingReferent(targetBlock);
						targetVertex = (verticesOfBlock.length != 0) ? verticesOfBlock[0]
								: new Vertex(targetBlock);
						Edge edge = new Edge(fromVertex, targetVertex);
						g.add(edge);
					}
				}
			}
		}
	}

	/**
	 * Partition the Model-M subroutine graph using the Model-P algorythm.
	 * The method createBlockGraph() must first be called to generate the
	 * initial Model-M graph.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@SuppressWarnings("unchecked")
	private void partitionGraph(TaskMonitor monitor) throws CancelledException {

		// make entry point list and set their source number attribute
		LinkedList<Vertex> entryList = new LinkedList<>();
		Vertex[] sources = g.getSources();

		for (Vertex source : sources) {
			entryList.addLast(source);
		}
		LinkedList<Vertex> todoStack = new LinkedList<>();

		boolean sourceListIsGrowing = true;

		while (sourceListIsGrowing) {

			sourceListIsGrowing = false;

			IntegerAttribute<Vertex> sourceNumber =
				(IntegerAttribute<Vertex>) vertexAttributes.createAttribute(SOURCE_NUMBER,
					attributeType);

			int cnt = entryList.size();
			for (int i = 0; i < cnt; i++) {
				todoStack.addLast(entryList.get(i)); // initialize stack with entry point
				while (!todoStack.isEmpty()) {  // traverse the graph from source

					if (monitor.isCancelled()) {
						throw new CancelledException();
					}

					Vertex v = todoStack.removeLast(); // pop vertex off todo stack

					sourceNumber.setValue(v, i + 1);
					Set<Vertex> children = g.getChildren(v);
					if (children.isEmpty()) {
						continue;
					}
					Iterator<Vertex> childIter = children.iterator();
					while (childIter.hasNext()) {
						Vertex child = childIter.next();

						// check to see if child has already been labeled
						//  if not, give it label of current source
						int sourceValue = 0;
						try {
							sourceValue = sourceNumber.getValue(child);
							if (sourceValue == i + 1) { // there's a cycle -- need to break out
								continue;
							}
						}
						catch (NoValueException nVE) {
							sourceValue = i + 1;
						}

						// If child's label is the same as the source, continue traversing graph
						// If child's label differs from source, we found a new entry point!
						//  In later case, don't traverse graph -- removing incoming edges
						//  and add to entryList
						if (sourceValue == i + 1) {
							todoStack.addLast(child);
						}
						else {
							// remove all edges going into child
							Set<Edge> incomingEdges = g.getIncomingEdges(child);
							Iterator<Edge> edgeIter = incomingEdges.iterator();
							while (edgeIter.hasNext()) {
								g.remove(edgeIter.next());
							}

							// add child to entryList
							entryList.addLast(child);

							// child has entry point
							entAttribute.setValue(child, 0);

							sourceListIsGrowing = true;
						}
					}
				}
			}
		}
	}

	/**
	 * Extract Model-P subroutines from Model-M subroutine graph following
	 * call to partitionGraph().
	 * @param monitor task monitor which allows user to cancel operation.
	 * @return array of Model-P subroutine blocks.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	private CodeBlock[] fromGraphToSubs(TaskMonitor monitor) throws CancelledException {

		DirectedGraph[] components = g.getComponents();
		CodeBlock[] subs = new CodeBlock[components.length];

		// Build the CodeBlock for each Model-P subroutine
		for (int i = 0; i < subs.length; i++) {

			if (monitor.isCancelled()) {
				throw new CancelledException();
			}

			GraphIterator<Vertex> vertIter = components[i].vertexIterator();
			AddressSet addrSet = new AddressSet();
			Address entry = null;

			// Follow all vertex references to build subroutine address set.
			// One of the vertices will be tagged as an entry point for each subroutine
			while (vertIter.hasNext()) {
				Vertex v = vertIter.next();
				CodeBlock block = (CodeBlock) g.getReferent(v);
				try {
					// check for entry point attribute
					int ix = entAttribute.getValue(v);
					Address[] entryPts = block.getStartAddresses();
					entry = entryPts[ix];
				}
				catch (NoValueException e) {
					// entry point not in this block/vertex
				}
				addrSet.add(block);
			}
			// Fabricate entry point if necessary
			if (entry == null) {
				entry = addrSet.getMinAddress();
				Msg.warn(this,
					"WARNING: fabricating entry point for Partitioned subroutine at " + entry);
			}
			subs[i] = createSub(addrSet, entry);
		}

		// delete all edges and verteces and attributes from graph
		entAttribute.clear();
		vertexAttributes.removeAttribute(ENTRY_POINT_TAG);
		vertexAttributes.removeAttribute(SOURCE_NUMBER);
		g.clear();

		return subs;
	}

	/**
	 * Generate a list of Model-P subroutines contained within a single Model-M subroutine.
	 * @param modelMSub a valid Model-M subroutine block.
	 * @return array of Model-P subroutines.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	private CodeBlock[] getModelPSubs(CodeBlock modelMSub, TaskMonitor monitor)
			throws CancelledException {
		createBlockGraph(modelMSub, monitor);
		partitionGraph(monitor);
		return fromGraphToSubs(monitor);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#getBasicBlockModel()
	 */
	@Override
	public CodeBlockModel getBasicBlockModel() {
		return modelM.getBasicBlockModel();
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#getName()
	 */
	@Override
	public String getName() {
		return NAME;
	}

	/**
	 * @see ghidra.program.model.block.SubroutineBlockModel#getBaseSubroutineModel()
	 */
	@Override
	public SubroutineBlockModel getBaseSubroutineModel() {
		return modelM;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#allowsBlockOverlap()
	 */
	@Override
	public boolean allowsBlockOverlap() {
		return false;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#externalsIncluded()
	 */
	@Override
	public boolean externalsIncluded() {
		return modelM.externalsIncluded();
	}

}
