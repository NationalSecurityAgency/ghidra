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

import java.util.ArrayList;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This BlockModel implements the simple block model.
 *
 * Each Codeblock is made up of contiguous instructions in address order.
 *
 *  Blocks satisfy the following:<ol>
 *   <li>Any instruction with a label starts a block.
 *   <li>Each instruction that could cause program control flow to change is the
 *       last instruction of a Codeblock.
 *   <li>All other instructions are "NOP" fallthroughs, meaning
 *      after execution the program counter will be at
 *      the instruction immediately following.
 *   <li>Any instruction that is unreachable and has no label is also considered the start
 *       of a block.
 * </ol>
 * So a CodeBlock in this model consists of contiguous code that has zero or
 * more nonflow fallthrough instructions followed by a single flow instruction.
 * Each block may or may not have a label at the first instruction, but may not
 * have a label at any other instruction contained in the block.
 *
 * This model does not implement the pure simple block model
 * because unreachable code is still considered a block.
 * 
 * This model handles delay slot instructions with the following 
 * assumptions:<ol>
 * <li>A delayed instruction is always corresponds to a change in
 *     flow and terminates a block.  The delay slot instructions
 *     following this instruction are always included with the
 *     block.  Therefor, delay slot instructions will always fall
 *     at the bottom of a simple block.
 * <li>The delay slot depth of the delayed instruction will always
 *     correspond to the number of delay slot instructions immediately
 *     following the instruction. The model may not behave properly if
 *     the disassembled code violates this assumption.
 * </ol>
 * @see ghidra.program.model.block.CodeBlockModel
 */
public class SimpleBlockModel implements CodeBlockModel {

	public static final String NAME = "Simple Block";
	protected final static CodeBlock[] emptyArray = new CodeBlock[0];

	protected Program program;
	protected Listing listing;
	protected ReferenceManager referenceMgr;
	protected AddressObjectMap foundBlockMap;
	protected final boolean includeExternals;

	protected static final boolean followIndirectFlows = true;

	/**
	 * Construct a SimpleBlockModel on a program.
	 * Externals will be excluded.
	 * @param program program to create blocks from.
	 */
	public SimpleBlockModel(Program program) {
		this(program, false);
	}

	/**
	 * Construct a SimpleBlockModel on a program.
	 * @param program program to create blocks from.
	 * @param includeExternals externals will be included if true
	 */
	public SimpleBlockModel(Program program, boolean includeExternals) {
		this.program = program;
		this.includeExternals = includeExternals;
		listing = program.getListing();
		referenceMgr = program.getReferenceManager();
		foundBlockMap = new AddressObjectMap();
	}

	/**
	 * Get the code/data block starting at this address.
	 *
	 * @param addr
	 * @param monitor task monitor which allows user to cancel operation.
	 * @return null if there is no codeblock starting at the address
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@Override
	public CodeBlock getCodeBlockAt(Address addr, TaskMonitor monitor) throws CancelledException {

		// First check out the Block cache
		Object blocks[] = foundBlockMap.getObjects(addr);
		if (blocks.length > 0) {
			CodeBlock block = (CodeBlock) blocks[0];
			Address[] entryPts = block.getStartAddresses();
			for (Address entryPt : entryPts) {
				if (block.getFirstStartAddress().equals(addr)) {
					return block;
				}
			}
		}

		if (addr.isExternalAddress()) {
			return includeExternals ? createSimpleExtBlock(addr) : null;
		}

		// handle instruction code block
		Instruction instr = listing.getInstructionAt(addr);
		if (instr != null) {
			// handle primary (top) entry point
			if (isBlockStart(instr)) {
				return getCodeBlockAt(instr, monitor);
			}

			// handle secondary entry point
			if (instr.getSymbols().length != 0) {
				return getFirstCodeBlockContaining(addr, monitor);
			}

			return null;
		}

		// handle data block
		Data data = listing.getDefinedDataAt(addr);
		if (data != null) {
			return createSimpleDataBlock(addr, data.getMaxAddress());
		}
		return null;
	}

	/**
	 * Get the basic code block starting at the specified instruction.
	 * @param instr first instruction of basic block
	 * @param monitor task monitor which allows user to cancel operation.
	 * @return null if there is no codeblock starting at the specified instruction
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	private CodeBlock getCodeBlockAt(Instruction instr, TaskMonitor monitor)
			throws CancelledException {

		Address begin = instr.getMinAddress();
		Address end = instr.getMaxAddress();
		ArrayList<Address> additionalEntryPts = new ArrayList<>();

		// skip past fall-through instructions
		// stop if block start found or non-fall-through instruction
		SymbolTable symTable = program.getSymbolTable();
		while (instr.hasFallthrough() && !hasEndOfBlockFlow(instr)) {
			if (monitor != null && monitor.isCancelled()) {
				throw new CancelledException();
			}
			Address fallThru = instr.getFallThrough();
			if (fallThru == null) {
				break;
			}
			Instruction nextInstr = listing.getInstructionAt(fallThru);

			if (nextInstr == null || symTable.hasSymbol(fallThru)) {
				break;
			}
			instr = nextInstr;
			end = instr.getMaxAddress();
		}
		Address exitPt = instr.getMinAddress();

		// if last instruction has delay slots, include them in block too
		int slotCnt = instr.getDelaySlotDepth();
		if (slotCnt != 0) {
			while (slotCnt > 0) {
				instr = instr.getNext();
				if (instr == null) {
					break;
				}
				--slotCnt;
				end = instr.getMaxAddress();
				Address addr = instr.getMinAddress();
				if (symTable.hasSymbol(addr)) {
					// Add delay slot entry point if necessary
					additionalEntryPts.add(addr);
				}
			}
		}

		// Check for labeled offcut instructions within last instruction
		else {
			try {
				Address chkAddr = exitPt.addNoWrap(1);
				SymbolIterator iter = symTable.getSymbolIterator(chkAddr, true);
				while (iter.hasNext()) {
					Symbol sym = iter.next();
					Address addr = sym.getAddress();
					if (addr.compareTo(end) > 0) {
						break;
					}
					Instruction ocInstr = listing.getInstructionAt(addr);
					if (ocInstr != null && ocInstr.getMaxAddress().compareTo(end) > 0) {
						additionalEntryPts.add(addr);
						end = ocInstr.getMaxAddress();
					}
				}
			}
			catch (AddressOverflowException e) {
			}
		}

		// Create and return block - keep min address as first entry point
		int cnt = additionalEntryPts.size();
		Address[] entryPts = new Address[cnt + 1];
		entryPts[0] = begin;
		for (int i = 0; i < cnt; i++) {
			entryPts[i + 1] = additionalEntryPts.get(i);
		}
		return createSimpleBlock(entryPts, begin, end);
	}

	/**
	 * Examine an instruction for out-bound flows which qualify it
	 * as an end-of-block. 
	 * @param instr
	 * @return true if end-of-block flow exists from specified instruction.
	 */
	protected boolean hasEndOfBlockFlow(Instruction instr) {

		if (instr.getFlowType() != RefType.FALL_THROUGH) {
			return true;
		}
		return referenceMgr.hasFlowReferencesFrom(instr.getMinAddress());
	}

	/**
	 * Create a new block over an address range with a single entry-point. 
	 * @param start the first address which is also the only entry-point.
	 * @param end the last address.
	 * @return CodeBlock
	 */
	protected CodeBlock createSimpleDataBlock(Address start, Address end) {
		return createSimpleBlock(new Address[] { start }, start, end);
	}

	/**
	 * Create a new block over an address range with one or more entry-points.
	 * @param entryPts an array of entry-point addresses for the block.
	 * @param begin the first address in the range.
	 * @param end last address in the range.
	 * @return CodeBlock
	 */
	private CodeBlock createSimpleBlock(Address[] entryPts, Address begin, Address end) {
		CodeBlock block = new CodeBlockImpl(this, entryPts, new AddressSet(begin, end));
		foundBlockMap.addObject(block, begin, end);
		return block;
	}

	private CodeBlock createSimpleExtBlock(Address extAddr) {
		CodeBlock block = new ExtCodeBlockImpl(this, extAddr);
		foundBlockMap.addObject(block, extAddr, extAddr);
		return block;
	}

	/**
	 * Get all the Code Blocks containing the address.
	 *
	 * @param addr   Address to find a containing block.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @return A SimpleBlock if any block contains the address
	 *        empty array otherwise.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@Override
	public CodeBlock[] getCodeBlocksContaining(Address addr, TaskMonitor monitor)
			throws CancelledException {
		CodeBlock block = getFirstCodeBlockContaining(addr, monitor);
		if (block == null) {
			return emptyArray;
		}
		CodeBlock[] arr = new CodeBlock[1];
		arr[0] = block;
		return arr;
	}

	/**
	 * Get the First Code Block that contains the address.
	 *
	 * @param addr   Address to find a containing block.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @return A SimpleBlock if any block contains the address.
	 *        null otherwise.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@Override
	public CodeBlock getFirstCodeBlockContaining(Address addr, TaskMonitor monitor)
			throws CancelledException {

		if (addr == null) {
			return null;
		}
		// First check out the Block cache
		Object blocks[] = foundBlockMap.getObjects(addr);
		if (blocks.length > 0) {
			return (CodeBlock) blocks[0];
		}

		if (addr.isExternalAddress()) {
			return getCodeBlockAt(addr, monitor);
		}

		Instruction instr = listing.getInstructionContaining(addr);
		if (instr != null) {

			// search backwards until instruction that starts a block is found
			Address fallFrom = instr.getFallFrom();
			while (!isBlockStart(instr, fallFrom)) {
				if (monitor != null && monitor.isCancelled()) {
					throw new CancelledException();
				}
				if (fallFrom == null) {
					Msg.warn(this, "WARNING: Invalid delay slot or offcut instruction found at " +
						instr.getMinAddress());
					try {
						fallFrom = instr.getMinAddress().subtractNoWrap(1);
					}
					catch (AddressOverflowException e) {
						break;
					}
				}
				instr = listing.getInstructionContaining(fallFrom);
				fallFrom = instr.getFallFrom();
			}
			return getCodeBlockAt(instr, monitor);
		}

		Data data = listing.getDefinedDataContaining(addr);
		if (data != null) {
			return getCodeBlockAt(data.getMinAddress(), monitor);
		}
		return null;
	}

	/**
	 * Get an iterator over the code blocks in the entire program.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@Override
	public CodeBlockIterator getCodeBlocks(TaskMonitor monitor) throws CancelledException {
		return new SimpleBlockIterator(this, monitor);
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
		return new SimpleBlockIterator(this, addrSet, monitor);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#getProgram()
	 */
	@Override
	public Program getProgram() {
		return program;
	}

	/**
	 * Returns the program listing associated with this model.
	 * @return the program listing associated with this model
	 */
	protected Listing getListing() {
		return listing;
	}

	/**
	 *  Return the addresses contained
	 *  in all instructions that are part of this block
	 *
	 * @param block code block to compute address set for.
	 */
//    public AddressSetView getAddressSet(CodeBlock block) {
//
//        if (!(block.getModel() instanceof SimpleBlockModel))
//            throw new IllegalArgumentException();
//
//        return new AddressSet((AddressSetView) block);
//    }

	/**
	 * Check if the instruction at the address is
	 * the start of a basic block.
	 *
	 * @param addr   Address to check
	 * @return true - if the address starts a basic block
	 *         false - otherwise
	 */
	protected boolean isBlockStart(Address addr) {
		// First check out the Block cache
		Object blocks[] = foundBlockMap.getObjects(addr);
		if (blocks.length > 0) {
			CodeBlock block = (CodeBlock) blocks[0];
			if (block.getFirstStartAddress().equals(addr)) {
				return true;
			}
		}

		// get instruction at address
		Instruction instr = listing.getInstructionAt(addr);

		if (instr != null) {
			return isBlockStart(instr);
		}

		Data data = listing.getDefinedDataAt(addr);
		return (data != null);
	}

	/**
	 * Check if the instruction starts a Simple block.
	 *
	 * @param instruction instruction to test if it starts a block
	 *
	 * @return true if this instruction is the start of a simple block.
	 */
	public boolean isBlockStart(Instruction instruction) {

		// If there is not a fall-from instruction, return true
		Address a = instruction.getFallFrom();
		return isBlockStart(instruction, a);
	}

	private boolean isBlockStart(Instruction instruction, Address fallFrom) {

		// If there is not a fall-from instruction
		if (fallFrom == null) {

			// if current instruction is offcut, it is not start
			try {
				Address addr = instruction.getMinAddress();
				Instruction chkInstr = listing.getInstructionContaining(addr.subtractNoWrap(1));
				if (chkInstr != null && chkInstr.getMaxAddress().compareTo(addr) >= 0) {
					return false;
				}
			}
			catch (AddressOverflowException e) {
			}
			return true;
		}

		Instruction previous = listing.getInstructionContaining(fallFrom);
		if (previous == null) {
			return true;
		}

		// blocks should never start on a delay start instruction
		// unless a from-from instruction does not exist.
		if (instruction == null || instruction.isInDelaySlot()) {
			return false;
		}

		// if previous instruction is offcut, current instruction is start
		try {
			Address addr = previous.getMinAddress();
			Instruction chkInstr = listing.getInstructionContaining(addr.subtractNoWrap(1));
			if (chkInstr != null && chkInstr.getMaxAddress().compareTo(addr) >= 0) {
				return true;
			}
		}
		catch (AddressOverflowException e) {
		}

		// If current instruction has a label, return true
		if (program.getSymbolTable().hasSymbol(instruction.getMinAddress())) {
			return true;
		}

		// If fall-from instruction has a flow-type reference, return true
		return !previous.hasFallthrough() || hasEndOfBlockFlow(previous);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#getName(ghidra.program.model.block.CodeBlock)
	 */
	@Override
	public String getName(CodeBlock block) {

		// get the start address for the block
		// look up the symbol in the symbol table.
		// it should have one if anyone calls it.
		// if not, make up a label

		if (!(block.getModel() instanceof SimpleBlockModel)) {
			throw new IllegalArgumentException();
		}

		Address start = block.getFirstStartAddress();

		Symbol symbol = program.getSymbolTable().getPrimarySymbol(start);
		if (symbol != null) {
			return symbol.getName();
		}

		return start.toString();
	}

	/**
	 * Return in general how things flow out of this node.
	 * If there are any abnormal ways to flow out of this node,
	 * (ie: jump, call, etc...) then the flow type of the node
	 * takes on that type.
	 *
	 * If there are multiple unique ways out of the node, then we
	 * should return FlowType.UNKNOWN (or FlowType.MULTIFLOW ?).
	 *
	 * Fallthrough is returned if that is the only way out.
	 *
	 * If this block really has no valid instructions, it can't flow,
	 * so FlowType.INVALID is returned.
	 *
	 * @return flow type of this node
	 */
	@Override
	public FlowType getFlowType(CodeBlock block) {

		if (!(block.getModel() instanceof SimpleBlockModel)) {
			throw new IllegalArgumentException();
		}

		// don't know the flow type yet, try to get the instruction type
		// of the last address in the block
		Instruction instr = listing.getInstructionContaining(block.getMaxAddress());
		if (instr != null) {

			// search backwards until a non-delay slot instruction is found
			while (instr.isInDelaySlot()) {
				Address fallFrom = instr.getFallFrom();
				if (fallFrom == null) {
					Msg.warn(this, "WARNING: Invalid delay slot instruction found at " +
						instr.getMinAddress());
					break;
				}
				instr = listing.getInstructionContaining(fallFrom);
			}
			FlowType flowType = instr.getFlowType();
			if (block.getStartAddresses().length > 1) {
				// modify flow type to a conditional	
				if (flowType == RefType.UNCONDITIONAL_CALL) {
					flowType = RefType.CONDITIONAL_CALL;
				}
				else if (flowType == RefType.UNCONDITIONAL_JUMP) {
					flowType = RefType.CONDITIONAL_JUMP;
				}
				else if (flowType.isTerminal()) {
					flowType = RefType.CONDITIONAL_TERMINATOR;
				}
			}
			else if (flowType.isFallthrough()) {
				// Use flow type associated with first flow-type reference
				Reference[] refs = referenceMgr.getFlowReferencesFrom(instr.getMinAddress());
				for (Reference ref : refs) {
					RefType refType = ref.getReferenceType();
					if (refType instanceof FlowType) {
						flowType = (FlowType) refType;
						break;
					}
				}
			}
			return flowType;
		}

		Data data = listing.getDefinedDataContaining(block.getMinAddress());
		if (data != null) {
			return RefType.INDIRECTION;
//            
//            // if no label here
//            Symbol sym = program.getSymbolTable().getSymbol(data.getMinAddress());
//            if (sym == null) {
//                return FlowType.INVALID;
//            }
//
//            // look at all refs to symbol, if not referred to by fallthrough
//            //  instruction, must be flow, so return true.
//            Referent refs[] = sym.getReferences();
//            if (refs == null) {
//                return FlowType.INVALID;
//            }
//            for (int i=0; i<refs.length; i++) {
//                Instruction refInstr = listing.getInstructionAt(refs[i].getAddress());
//                if (refInstr == null || refInstr.getFlowType().isFallthrough()) {
//                    continue;
//                }
//                return refInstr.getFlowType();
//            }
		}

		return RefType.INVALID;
	}

	/**
	 * Get an iterator over source blocks flowing into this block.
	 * @param block code block to get the source iterator for.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@Override
	public CodeBlockReferenceIterator getSources(CodeBlock block, TaskMonitor monitor)
			throws CancelledException {

		// get the instruction before this block
		//    if it is contiguous and falls through, then it is a source
		// get the symbol at the start address
		//    if there is a symbol, use the references to it for sources
		// a block with a symbol can be fallen to from above.

		if (block == null) {
			return null;
		}

		if (!(block.getModel() instanceof SimpleBlockModel)) {
			throw new IllegalArgumentException();
		}

		return new SimpleSourceReferenceIterator(block, followIndirectFlows, monitor);
	}

	/**
	 * Get number of source blocks flowing into this block
	 *
	 * @param block code block to get the source iterator for.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @throws CancelledException if the monitor cancels the operation.
	 * @deprecated this method should be avoided since it repeats the work of the getSources iterator
	 */
	@Override
	@Deprecated
	public int getNumSources(CodeBlock block, TaskMonitor monitor) throws CancelledException {

		// get the instruction before this block
		//    if it is contiguous and falls through, then has at least 1 source
		// get the symbol at the start address
		//    add the number of references to the count

		if (block == null) {
			return 0;
		}

		if (!(block.getModel() instanceof SimpleBlockModel)) {
			throw new IllegalArgumentException();
		}

		return SimpleSourceReferenceIterator.getNumSources(block, followIndirectFlows, monitor);
	}

	/**
	 * Get an iterator over destination blocks flowing from this block.
	 *
	 * @param block code block to get the destination block iterator for.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	@Override
	public CodeBlockReferenceIterator getDestinations(CodeBlock block, TaskMonitor monitor)
			throws CancelledException {
		// destinations of Fallthroughs are the follow on block
		//    destinations of all others are the instruction's operand referents

		// simple way:
		//   for each operand
		//      get it's type
		//      for each one that references code
		//         get all its references
		//            add those references to the iterator
		// more complex:
		//    destinations of all others are the instruction's operand referents
		//       could probably get this out of the symbol table using getReferentAt(address)

		// problem: can't assume that a fallthrough actually falls through to valid block
		//          nor that any destination is a good destination unless the instruction
		//          is looked at.

		if (block == null) {
			return null;
		}

		if (!(block.getModel() instanceof SimpleBlockModel)) {
			throw new IllegalArgumentException();
		}

		return new SimpleDestReferenceIterator(block, followIndirectFlows, monitor);
	}

	/**
	 * Get number of destination blocks flowing out of this block
	 *
	 * @param block code block to get the destination block iterator for.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @throws CancelledException if the monitor cancels the operation.
	 * @deprecated this method should be avoided since it repeats the work of the getDestinations iterator
	 */
	@Override
	@Deprecated
	public int getNumDestinations(CodeBlock block, TaskMonitor monitor) throws CancelledException {

		if (block == null) {
			return 0;
		}

		if (!(block.getModel() instanceof SimpleBlockModel)) {
			throw new IllegalArgumentException();
		}

		return SimpleDestReferenceIterator.getNumDestinations(block, followIndirectFlows, monitor);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#getBasicBlockModel()
	 */
	@Override
	public CodeBlockModel getBasicBlockModel() {
		return this;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#getName()
	 */
	@Override
	public String getName() {
		return NAME;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockModel#allowsBlockOverlap()
	 */
	@Override
	public boolean allowsBlockOverlap() {
		return false;
	}

	@Override
	public boolean externalsIncluded() {
		return includeExternals;
	}

}
