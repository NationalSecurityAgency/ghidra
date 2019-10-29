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
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <CODE>MultEntSubModel</CODE> (M-model) defines subroutines which do not share code with
 * any other subroutine and may have one or more entry points. Each entry-
 * points represent either a source or called entry-point.
 * <P>
 * MODEL-M subroutines should be used to determine which subroutine(s) contains
 * a particular instruction.
 * Since model-M subroutines yield the largest subroutines, they should be particular useful
 * in the process of program slicing -- the process of splitting the program into modules
 * or subroutine cliques -- in order to begin to understand the structure and functionality
 * of the program.
 */
public class MultEntSubModel implements SubroutineBlockModel {

	public static final String NAME = "Multiple Entry";

	protected Program program;
	protected Listing listing;

	private AddressObjectMap foundMSubs;      // used for caching model-M subroutines
	private CodeBlockModel bbModel;           // basic block model
	protected final boolean includeExternals;

	/**
	 * Construct a <CODE>MultEntSubModel</CODE> for a program.
	 *
	 * @param program program to create blocks from.
	 */
	public MultEntSubModel(Program program) {
		this(program, false);
	}

	/**
	 * Construct a <CODE>MultEntSubModel</CODE> for a program.
	 * @param program program to create blocks from.
	 * @param includeExternals external blocks will be included if true
	 */
	public MultEntSubModel(Program program, boolean includeExternals) {
		this.program = program;
		this.includeExternals = includeExternals;
		listing = program.getListing();
		foundMSubs = new AddressObjectMap();
	}

	/**
	 * Get the code block that has an entry point at addr.
	 *
	 * @param addr one of the entry points for a Model-M subroutine
	 * @param monitor task monitor which allows user to cancel operation.
	 * @return null if there is no subroutine with an entry at addr.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@Override
	public CodeBlock getCodeBlockAt(Address addr, TaskMonitor monitor) throws CancelledException {

		if (addr == null) {
			return null;
		}

		CodeBlock block = getSubFromCache(addr);
		if (block == null) {
			block = getAddressSetContaining(addr, monitor);
		}
		if (block != null) {
			Address[] entPts = block.getStartAddresses();
			for (Address entPt : entPts) {
				if (entPt.equals(addr)) {
					return block;
				}
			}
		}
		return null;
	}

	/**
	 * Get the M-Model subroutine address set which contains the specified address.
	 * This method also identifies the entry points and caches the resulting CodeBlock.
	 *
	 * @param   addr    Address inside the subroutine that we are seeking
	 * @param monitor task monitor which allows user to cancel operation.
	 * @return          The <CODE>CodeBlock</CODE> for a
	 *                  <CODE>MultEntSubModel</CODE> Subroutine.
	 * 					Null is returned if there is no instruction at addr.
	 * @throws CancelledException if the monitor cancels the operation.
	 **/
	protected CodeBlock getAddressSetContaining(Address addr, TaskMonitor monitor)
			throws CancelledException {

		if (addr.isExternalAddress()) {
			if (includeExternals) {
				CodeBlock block = new ExtCodeBlockImpl(this, addr);
				foundMSubs.addObject(block, addr, addr);
				return block;
			}
			return null;
		}

		// create a holder for the blockSet
		AddressSet addrSet = new AddressSet();

		// Use a new block model each time, so that only the current
		//  function basic blocks will get saved.
		bbModel = new SimpleBlockModel(program, includeExternals);

		// Create the todoStack and initialize it with instr; also initialize the list for entryPts.
		ArrayList<Address> entryPtList = new ArrayList<Address>();
		LinkedList<Address> todoList = new LinkedList<Address>();   // list of address destinations to follow
		LinkedList<CodeBlock> srcList = new LinkedList<CodeBlock>();    // list of blocks to process for possible sources
		todoList.addFirst(addr);

		// Build model-M subroutine from basic blocks
		while (!todoList.isEmpty() || !srcList.isEmpty()) {

			if (monitor != null && monitor.isCancelled()) {
				throw new CancelledException();
			}

			// if todoList is empty
			//      process any blocks for sources that we put off to analyze later
			//   It is easier/efficient to follow flow in the forward direction.
			if (todoList.isEmpty()) {
				while (todoList.isEmpty() && !srcList.isEmpty()) {
					CodeBlock bblock = srcList.removeFirst();
					// Process all block source references
					addSources(monitor, entryPtList, todoList, bblock);
				}
				continue;
			}

			// get the next address to process
			Address a = null;
			a = todoList.removeFirst();

			// Get basic block at the specified address
			if (addrSet.contains(a)) {
				continue; // already processed this block  
			}

			CodeBlock bblock = bbModel.getFirstCodeBlockContaining(a, monitor);
			if (bblock == null) {
				continue;
			}

			// Verify that the block contains instructions
			if (listing.getInstructionAt(bblock.getMinAddress()) == null) {
				continue;
			}

			// Add basic block to subroutine address set
			addrSet.add(bblock);

			// Process all destination references
			addDestinations(monitor, todoList, bblock);

			// add block to list of block to process later
			srcList.addLast(bblock);
		}

		if (addrSet.isEmpty()) {
			return null;
		}

		// Check for failure to find entry point
		if (entryPtList.size() == 0) {
			Msg.warn(this, "Failed to find entry point for subroutine containing " + addr);
			entryPtList.add(addrSet.getMinAddress());
		}
		Address[] entryPts = new Address[entryPtList.size()];
		entryPtList.toArray(entryPts);

		CodeBlock block = new CodeBlockImpl(this, entryPts, addrSet);
		foundMSubs.addObject(block, addrSet);

		return block;
	}

	private void addDestinations(TaskMonitor monitor, LinkedList<Address> todoList,
			CodeBlock bblock) throws CancelledException {
		CodeBlockReferenceIterator destIter = bblock.getDestinations(monitor);
		while (destIter.hasNext()) {
			CodeBlockReference destRef = destIter.next();
			// Add Jump and Fall-through destinations to the todoList
			Address destAddr = destRef.getDestinationAddress();
			if (destAddr.isMemoryAddress()) {
				FlowType refFlowType = destRef.getFlowType();
				if (refFlowType.isJump()) {
					todoList.addLast(destAddr);
				}
				else if (refFlowType.isFallthrough()) {
					todoList.addFirst(destAddr);
				}
			}
		}
	}

	private void addSources(TaskMonitor monitor, List<Address> entryPtList,
			LinkedList<Address> todoList, CodeBlock bblock) throws CancelledException {
		CodeBlockReferenceIterator srcIter = bblock.getSources(monitor);
		boolean isSource = true;
		boolean isEntry = false;
		while (srcIter.hasNext()) {
			isSource = false;
			CodeBlockReference srcRef = srcIter.next();
			FlowType refFlowType = srcRef.getFlowType();
			if (refFlowType.isJump() || refFlowType.isFallthrough()) {
				// Add Jump and Fall-through sources to the todoList
				todoList.addLast(srcRef.getSourceAddress());
			}
			else if (refFlowType.isCall()) {
				// Basic block is a subroutine entry point
				isEntry = true;
			}
		}
		if (isSource || isEntry) {
			entryPtList.add(bblock.getMinAddress());
		}
	}

	/**
	 * Get the MultEntSubModel Code Block that contains the address.
	 *
	 * @param addr   Address to find a containing block.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @return A CodeBlock if any block contains the address.
	 *         null otherwise.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@Override
	public CodeBlock getFirstCodeBlockContaining(Address addr, TaskMonitor monitor)
			throws CancelledException {

		CodeBlock block = getSubFromCache(addr);
		if (block == null) {
			block = getAddressSetContaining(addr, monitor);
		}
		return block;
	}

	/**
	 * Returns the one code block contained by addr (only for
	 *  a model that has shared subroutines would this method
	 *  return more than one code block)
	 *
	 * @param addr   Address to find a containing block.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @return A CodeBlock if any block contains the address.
	 *         empty array otherwise.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@Override
	public CodeBlock[] getCodeBlocksContaining(Address addr, TaskMonitor monitor)
			throws CancelledException {
		CodeBlock sub = getFirstCodeBlockContaining(addr, monitor);
		if (sub == null) {
			return emptyBlockArray;
		}
		CodeBlock[] blocks = new CodeBlock[1];
		blocks[0] = sub;
		return blocks;
	}

	/**
	 * Get an iterator over the code blocks in the entire program.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@Override
	public CodeBlockIterator getCodeBlocks(TaskMonitor monitor) throws CancelledException {
		return new MultEntSubIterator(this, monitor);
	}

	/**
	 * Get an iterator over CodeBlocks which overlap the specified address set.
	 *
	 * @param addrSet   an address set within program
	 * @param monitor task monitor which allows user to cancel operation.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@Override
	public CodeBlockIterator getCodeBlocksContaining(AddressSetView addrSet, TaskMonitor monitor)
			throws CancelledException {
		return new MultEntSubIterator(this, addrSet, monitor);
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
	 * @return the listing associated with this block model.
	 */
	public Listing getListing() {
		return listing;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#getName(ghidra.program.model.block.CodeBlock)
	 */
	@Override
	public String getName(CodeBlock block) {

		if (!(block.getModel() instanceof MultEntSubModel)) {
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

		return "SOURCE_SUB" + start.toString();
	}

	/**
	 * Return in general how things flow out of this node.
	 * This method exists for the SIMPLEBLOCK model.
	 *
	 * <p>
	 * Since it doesn't make a great deal of sense to ask for this method
	 * in the case of subroutines, we return FlowType.UNKNOWN
	 * as long as the block exists.
	 *
	 * <p>
	 * If this block has no valid instructions, it can't flow,
	 * so FlowType.INVALID is returned.
	 *
	 * @return flow type of this node
	 */
	@Override
	public FlowType getFlowType(CodeBlock block) {

		if (!(block.getModel() instanceof MultEntSubModel)) {
			throw new IllegalArgumentException();
		}

		/* If there are multiple unique ways out of the node, then we
		    should return FlowType.UNKNOWN (or FlowType.MULTIFLOW ?).
		   Possible considerations for the future which are particularly
		    applicable to model-P subroutines: add FlowType.MULTICALL if
		    only calls out and FlowType.MULTIJUMP if multiple jumps OUT
		    (as opposed to jumping within the subroutine).
		    Might want to consider FlowType.MULTITERMINAL for multiple returns? */

		return RefType.FLOW;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#getSources(ghidra.program.model.block.CodeBlock, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public CodeBlockReferenceIterator getSources(CodeBlock block, TaskMonitor monitor)
			throws CancelledException {
		if (!(block.getModel() instanceof MultEntSubModel)) {
			throw new IllegalArgumentException();
		}

		return new SubroutineSourceReferenceIterator(block, monitor);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#getNumSources(ghidra.program.model.block.CodeBlock, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public int getNumSources(CodeBlock block, TaskMonitor monitor) throws CancelledException {

		if (!(block.getModel() instanceof MultEntSubModel)) {
			throw new IllegalArgumentException();
		}

		return SubroutineSourceReferenceIterator.getNumSources(block, monitor);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#getDestinations(ghidra.program.model.block.CodeBlock, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public CodeBlockReferenceIterator getDestinations(CodeBlock block, TaskMonitor monitor)
			throws CancelledException {

		if (!(block.getModel() instanceof MultEntSubModel)) {
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

		if (!(block.getModel() instanceof MultEntSubModel)) {
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
	public AddressSetView getAddressSet(CodeBlock block) {

		if (!(block.getModel() instanceof MultEntSubModel)) {
			throw new IllegalArgumentException();
		}

		return new AddressSet(block);
	}

	/**
	 *  Gets a subroutine from the cache containing addr.  If none there, returns null.
	 *  It is assumed that an address will only occur within a single MSub
	 */
	private CodeBlock getSubFromCache(Address addr) {
		Object[] mapObjs = this.foundMSubs.getObjects(addr);
		return mapObjs.length == 0 ? null : (CodeBlock) mapObjs[0];
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#getBasicBlockModel()
	 */
	@Override
	public CodeBlockModel getBasicBlockModel() {
		if (bbModel == null) {
			bbModel = new SimpleBlockModel(program);
		}
		return bbModel;
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
		return this;
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
		return includeExternals;
	}

}
