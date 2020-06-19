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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <CODE>IsolatedEntryCodeSubModel</CODE> (S-model) defines subroutines with a
 * unique entry point, which may share code with other subroutines. Each entry-
 * point may either be a source or called entry-point and is identified using
 * the MultEntSubModel. This model extends the OverlapCodeSubModel, redefining
 * the set of addresses contained within each subroutine. Unlike the
 * OverlapCodeSubModel, the address set of a IsolatedEntryCodeSubModel
 * subroutine is permitted to span entry-points of other subroutines based upon
 * the possible flows from its entry- point.
 *
 * @see ghidra.program.model.block.CodeBlockModel
 * @see ghidra.program.model.block.OverlapCodeSubModel
 * @see ghidra.program.model.block.MultEntSubModel
 */
public class IsolatedEntrySubModel extends OverlapCodeSubModel {

	public static final String ISOLATED_MODEL_NAME = "Isolated Entry";
	
    /**
     * Construct a <CODE>IsolatedEntrySubModel</CODE> subroutine on a program.
     *
     * @param program program to create blocks from.
     */
    public IsolatedEntrySubModel(Program program) {
        super(program);
    }
    
    /**
     * Construct a <CODE>IsolatedEntrySubModel</CODE> subroutine on a program.
     *
     * @param program program to create blocks from.
     * @param includeExternals externals are included if true
     */
    public IsolatedEntrySubModel(Program program, boolean includeExternals) {
        super(program, includeExternals);
    }

	/**
     * Get the subroutine code block which starts at the specified address which
     * is an entry point of a Model-M subroutine.
     * 
     * Classes which extend this class should implement this method.
     *
     * @param   mStartAddr = a Model-M subroutine entry point.
     * @param monitor task monitor which allows user to cancel operation.
     * @return  a subroutine code block
     * @throws CancelledException if the monitor cancels the operation.
     */
    @Override
    protected CodeBlock getSubroutine(Address mStartAddr, TaskMonitor monitor) throws CancelledException {
    	
    	// Create address list which contains all other entry points for this M-model sub
        CodeBlock mSub = modelM.getCodeBlockAt(mStartAddr, monitor);
        if (mSub == null) {
			return null;
		}
        Address[] mEntryPts = mSub.getStartAddresses();
        ArrayList<Address> startSet = new ArrayList<Address>();
        for (Address mEntryPt : mEntryPts) {
            if (!mStartAddr.equals(mEntryPt)) {
				startSet.add(mEntryPt);
			}
        }

		// create a holder for the blockSet
        AddressSet addrSet = new AddressSet();
        
        // Create the todoStack and initialize it with instr; also initialize the list for entryPts.
        LinkedList<Address> todoList = new LinkedList<Address>();
        todoList.addFirst(mStartAddr);
        
        CodeBlockModel bbModel = modelM.getBasicBlockModel();
        
        // Build model-S subroutine from basic blocks
        while (!todoList.isEmpty()) {
        
        	if (monitor.isCancelled()) {
				throw new CancelledException();
			}
        		
        	// Get basic block at the specified address 
        	Address a = todoList.removeLast();  
        	if (addrSet.contains(a) || startSet.contains(a))
			 {
				continue; // already processed this block or encountered another Model-M entry point  
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
	 * @see ghidra.program.model.block.CodeBlockModel#getName()
	 */
	@Override
    public String getName() {
		return ISOLATED_MODEL_NAME;
	}

}
