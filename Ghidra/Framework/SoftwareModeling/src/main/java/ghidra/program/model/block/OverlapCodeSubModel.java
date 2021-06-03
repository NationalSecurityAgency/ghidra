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
import java.util.LinkedList;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <CODE>OverlapCodeSubModel</CODE> (O-model) defines subroutines with a
 * unique entry point, which may share code with other subroutines. Each entry-
 * point may either be a source or called entry-point and is identified using
 * the MultEntSubModel.  This model defines the set of addresses contained
 * within each subroutine based upon the possible flows from its entry- point.
 * Flows which encounter another entry-point are terminated.
 * <P>
 * NOTE: This differs from the original definition of an entry point, however,
 * the intent of the O-Model is preserved.
 *
 * @see ghidra.program.model.block.CodeBlockModel
 * @see ghidra.program.model.block.MultEntSubModel
 */
public class OverlapCodeSubModel implements SubroutineBlockModel {

	public static final String OVERLAP_MODEL_NAME = "Overlapped Code";
	
    protected Program program;
    protected Listing listing;
    protected CodeBlockCache foundOSubs;
    protected MultEntSubModel modelM;

    /**
     * Construct a <CODE>OverlapCodeSubModel</CODE> subroutine on a program.
     * @param program program to create blocks from.
     */
    public OverlapCodeSubModel(Program program) {
        this(program, false);
    }
    
    /**
     * Construct a <CODE>OverlapCodeSubModel</CODE> subroutine on a program.
     * @param program program to create blocks from.
     * @param includeExternals external blocks will be included if true
     */
    public OverlapCodeSubModel(Program program, boolean includeExternals) {
        this.program = program;
        listing = program.getListing();
        foundOSubs = new CodeBlockCache();
        modelM = new MultEntSubModel(program, includeExternals);
    }
    
    /**
     *  Compute an address set that represents all the addresses contained
     *  in all instructions that are part of this block
     *
     * @param block code block to compute address set for.
     */
//    public AddressSetView getAddressSet(CodeBlock block) {
//        return new AddressSet((AddressSetView) block);
//    }

    /**
     *  Get the subroutine code block which starts at the specified address which 
     *  is an entry point of a Model-M subroutine.
     * 
     *  Classes which extend this class should implement this method.
     *
     * @param   mStartAddr = a Model-M subroutine entry point.
     * @param monitor task monitor which allows user to cancel operation.
     * @return  a subroutine code block or null if not found.
     * @throws CancelledException if the monitor cancels the operation.
     */
    protected CodeBlock getSubroutine(Address mStartAddr, TaskMonitor monitor) throws CancelledException {
    	
		// create a holder for the blockSet
        AddressSet addrSet = new AddressSet();
        
        // Create the todoStack and initialize it with instr; also initialize the list for entryPts.
        LinkedList<Address> todoList = new LinkedList<Address>();
        todoList.addFirst(mStartAddr);
        
        CodeBlockModel bbModel = modelM.getBasicBlockModel();
        
        // Build model-O subroutine from basic blocks
        while (!todoList.isEmpty()) {
        	
        	if (monitor.isCancelled()) {
				throw new CancelledException();
			}
        
        	// Get basic block at the specified address 
        	Address a = todoList.removeLast();  
        	if (addrSet.contains(a))
			 {
				continue; // already processed this block   
			}
	        CodeBlock bblock = bbModel.getFirstCodeBlockContaining(a, monitor);
	        if (bblock == null) {
				continue;
			}
	        	
	        // Verify that the block contains instructions
	        if (listing.getInstructionAt(a) == null) {
				continue;
			}
	        	
	        // Add basic block to subroutine address set
	        addrSet.add(bblock);
        
        	// Process all destination references
        	CodeBlockReferenceIterator destIter = bblock.getDestinations(monitor);
        	while (destIter.hasNext()) {
        		CodeBlockReference destRef = destIter.next();
        		FlowType refFlowType = destRef.getFlowType();
        		if (refFlowType.isJump() || refFlowType.isFallthrough())
	            {
	            	// Add Jump and Fall-through destinations to the todoList
	            	todoList.add(destRef.getDestinationAddress());	
	            }
        	}       	
        } 	
    	return createSub(addrSet, mStartAddr);
    }

    /**
     * @see ghidra.program.model.block.CodeBlockModel#getCodeBlockAt(ghidra.program.model.address.Address, ghidra.util.task.TaskMonitor)
     */
    @Override
	public CodeBlock getCodeBlockAt(Address addr, TaskMonitor monitor) throws CancelledException {

        // First check out the Block cache
        CodeBlock block = foundOSubs.getBlockAt(addr);
        if (block != null) {
            return block;
        }

        CodeBlock modelMSub = modelM.getCodeBlockAt(addr, monitor);
        if (modelMSub != null) {
            Address[] entPts = modelMSub.getStartAddresses();
            if (entPts.length == 1){
                return createSub(modelMSub, addr);
            }
            return getSubroutine(addr, monitor);
        }
        return null;
    }


    /**
     * Get all the Code Blocks containing the address.
     * Model-O is the only of the MOP models that allows for there to be more than one
     *
     * @param addr   Address to find a containing block.
     * @param monitor task monitor which allows user to cancel operation.
     * @return A CodeBlock array with one entry containing the subroutine that
     *              contains the address empty array otherwise.
     * @throws CancelledException if the monitor cancels the operation.
     */
    @Override
	public CodeBlock[] getCodeBlocksContaining(Address addr, TaskMonitor monitor) throws CancelledException {

        // First check out the Block cache
        CodeBlock[] blocks = foundOSubs.getBlocksContaining(addr);
        if (blocks != null && blocks[0] != null) {
            return blocks;
        }

        CodeBlock modelMSub = modelM.getFirstCodeBlockContaining(addr, monitor);
        if (modelMSub == null) {
			return emptyBlockArray;
		}
        Address[] entPts = modelMSub.getStartAddresses();

        // Single-entry MSub same as OSub
        int cnt = entPts.length;
        if (cnt == 1){
            blocks = new CodeBlock[1];
            blocks[0] = createSub(modelMSub, entPts[0]);
            return blocks;
        }

        // Return all OSubs - one per entry point
        ArrayList<CodeBlock> blockList = new ArrayList<CodeBlock>();
        for (int i = 0; i < cnt; i++) {
            CodeBlock block = getSubroutine(entPts[i], monitor);
            if (block.contains(addr)) {
				blockList.add(block);
			}
        }
        return blockList.toArray(new CodeBlock[blockList.size()]);
    }


    /**
     * @see ghidra.program.model.block.CodeBlockModel#getFirstCodeBlockContaining(ghidra.program.model.address.Address, ghidra.util.task.TaskMonitor)
     */
    @Override
	public CodeBlock getFirstCodeBlockContaining(Address addr, TaskMonitor monitor) throws CancelledException {

        // First check out the Block cache
        CodeBlock block = foundOSubs.getFirstBlockContaining(addr);
        if (block != null) {
            return block;
        }

        CodeBlock modelMSub = modelM.getFirstCodeBlockContaining(addr, monitor);
        if (modelMSub == null) {
			return null;
		}
        Address[] entPts = modelMSub.getStartAddresses();

        // Single-entry MSub same as OSub
        int cnt = entPts.length;
        if (cnt == 1){
            return createSub(modelMSub, entPts[0]);
        }

        // Return first OSub which contains addr
        for (int i = 0; i < cnt; i++) {
            block = getSubroutine(entPts[i], monitor);
            if (block != null && block.contains(addr)) {
				return block;
			}
        }
        return null;
    }

    /**
     * @see ghidra.program.model.block.CodeBlockModel#getCodeBlocks(ghidra.util.task.TaskMonitor)
     */
    @Override
	public CodeBlockIterator getCodeBlocks(TaskMonitor monitor) throws CancelledException {
        return new SingleEntSubIterator(this, monitor);
    }

    /**
     * @see ghidra.program.model.block.CodeBlockModel#getCodeBlocksContaining(ghidra.program.model.address.AddressSetView, ghidra.util.task.TaskMonitor)
     */
    @Override
	public CodeBlockIterator getCodeBlocksContaining(AddressSetView addrSet, TaskMonitor monitor) throws CancelledException {
        return new SingleEntSubIterator(this, addrSet, monitor);
    }

    /**
     * Returns the Multiple Entry Block Model used by this model.
     * @return the Multiple Entry Block Model used by this model
     */
    protected MultEntSubModel getModelM() {
        return modelM;
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
        // get the start address for the block
        // look up the symbol in the symbol table.
        // it should have one if anyone calls it.
        // if not, make up a label

        if (!(block.getModel() instanceof OverlapCodeSubModel)) {
			throw new IllegalArgumentException();
		}

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
        /* If there are multiple unique ways out of the node, then we
            should return FlowType.UNKNOWN (or FlowType.MULTIFLOW ?).
           Possible considerations for the future which are particularly
            applicable to model-P subroutines: add FlowType.MULTICALL if
            only calls out and FlowType.MULTIJUMP if multiple jumps OUT
            (as opposed to jumping within the subroutine).
            Might want to consider FlowType.MULTITERMINAL for multiple returns? */

        if (!(block.getModel() instanceof OverlapCodeSubModel)) {
			throw new IllegalArgumentException();
		}

        return RefType.FLOW;
    }

    /**
     * @see ghidra.program.model.block.CodeBlockModel#getSources(ghidra.program.model.block.CodeBlock, ghidra.util.task.TaskMonitor)
     */
    @Override
	public CodeBlockReferenceIterator getSources(CodeBlock block, TaskMonitor monitor) throws CancelledException {

        if (!(block.getModel() instanceof OverlapCodeSubModel)) {
			throw new IllegalArgumentException();
		}

        return new SubroutineSourceReferenceIterator(block, monitor);
    }

    /**
     * @see ghidra.program.model.block.CodeBlockModel#getNumSources(ghidra.program.model.block.CodeBlock, ghidra.util.task.TaskMonitor)
     */
    @Override
	public int getNumSources(CodeBlock block, TaskMonitor monitor) throws CancelledException {
    	
    	if (!(block.getModel() instanceof OverlapCodeSubModel)) {
			throw new IllegalArgumentException();
		}
            
    	return SubroutineSourceReferenceIterator.getNumSources(block, monitor);
    }

    /**
     * @see ghidra.program.model.block.CodeBlockModel#getDestinations(ghidra.program.model.block.CodeBlock, ghidra.util.task.TaskMonitor)
     */
    @Override
	public CodeBlockReferenceIterator getDestinations(CodeBlock block, TaskMonitor monitor) throws CancelledException {
        // destinations of Fallthroughs are the follow on block
        //    destinations of all others are the instruction's operand referents

        // Call way:
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

        if (!(block.getModel() instanceof OverlapCodeSubModel)) {
			throw new IllegalArgumentException();
		}

        return new SubroutineDestReferenceIterator(block, monitor);
    }

    /**
     * @see ghidra.program.model.block.CodeBlockModel#getNumDestinations(ghidra.program.model.block.CodeBlock, ghidra.util.task.TaskMonitor)
     */
    @Override
	public int getNumDestinations(CodeBlock block, TaskMonitor monitor) throws CancelledException {

        if (!(block.getModel() instanceof OverlapCodeSubModel)) {
			throw new IllegalArgumentException();
		}

		return SubroutineDestReferenceIterator.getNumDestinations(block, monitor);
    }

    /**
     *  Create a new Subroutine which has specified address set and entry point.
     *  Cache the model-O subroutine.
     *  @param  addrSet contains the address set of the model-O subroutine
     *  @param entryPt the OSub entry point.
     *  @return subroutine block that was created
     */
    protected CodeBlock createSub(AddressSetView addrSet, Address entryPt) {
    	
    	if (addrSet.isEmpty()) {
			return null;
		}
			
        Address[] entryPts = new Address[1];
        entryPts[0] = entryPt;

        CodeBlock block = new CodeBlockImpl(this, entryPts, addrSet);
        foundOSubs.addObject(block, addrSet);

        return block;
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
		return OVERLAP_MODEL_NAME;
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
		return true;
	}

	@Override
	public boolean externalsIncluded() {
		return modelM.externalsIncluded();
	}

}
