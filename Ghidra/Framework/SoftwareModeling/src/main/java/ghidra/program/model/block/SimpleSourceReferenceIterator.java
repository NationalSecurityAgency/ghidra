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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.LinkedList;

/**
 * SimpleSourceReferenceIterator is a unidirectional iterator over the <CODE>CodeBlockReference</CODE>s
 * for a CodeBlock.  It is <B>not</B> failfast, whenever <CODE>hasNext()</CODE>
 * are called it will find if there is a next <CODE>CodeBlockReference</CODE> and acquire
 * a handle if there is one. If new code units are added to the listing after
 * the iterator is created it will find them as it scans ahead.
 */
public class SimpleSourceReferenceIterator implements CodeBlockReferenceIterator {
	
    // queue of discovered source block references
	private LinkedList<CodeBlockReferenceImpl> blockRefQueue = new LinkedList<CodeBlockReferenceImpl>();
	private TaskMonitor monitor;

    /**
     * Construct an Iterator over Source blocks for a CodeBlock.
     *
     * @param block block to get destination blocks for.  This should be a
     * block obtained from SimpleBlockModel.
     * @param followIndirectFlows indirect references will only be included if true
     * @param monitor task monitor which allows user to cancel operation.
     * @throws CancelledException if the monitor cancels the operation.
     */
    public SimpleSourceReferenceIterator(CodeBlock block, boolean followIndirectFlows, TaskMonitor monitor) throws CancelledException {
    	this.monitor = monitor;
		getSources(block, blockRefQueue, followIndirectFlows, monitor);
    }

    /**
     * @see ghidra.program.model.block.CodeBlockReferenceIterator#next()
     */
    public CodeBlockReference next() throws CancelledException {
    	monitor.checkCanceled();
    	return (blockRefQueue.isEmpty() ? null : blockRefQueue.removeFirst());
    }

    /**
     * @see ghidra.program.model.block.CodeBlockReferenceIterator#hasNext()
     */
    public boolean hasNext() throws CancelledException {
    	monitor.checkCanceled();
		return !blockRefQueue.isEmpty();
    }
    
    /**
     * Get number of source references flowing from this subroutine (block).
     * All Calls to this block, and all external FlowType block references
     * to this block are counted.
     * 
     * @param block code block to get the number of source references to.
     * @param followIndirectFlows indirect references will only be included if true
     * @param monitor task monitor which allows user to cancel operation.
     * @throws CancelledException if the monitor cancels the operation.
     * @deprecated this method should be avoided since it repeats the work of the iterator
     */
	@Deprecated
    public static int getNumSources(CodeBlock block, boolean followIndirectFlows, TaskMonitor monitor) throws CancelledException {
    	return getSources(block, null, followIndirectFlows, monitor);
    }
    
    /**
     * Count and queue all source references flowing from this block.
     * All Calls to this block, and all external FlowType block references
     * to this block are counted.
     * 
     * @param block code block to get the number of source references to.
     * @param blockRefQueue the CodeBlockReference queue, may be null
     * @param followIndirectFlows indirect references will only be included if true
     * @param monitor task monitor which allows user to cancel operation.
     * @throws CancelledException if the monitor cancels the operation.
     */
    private static int getSources(CodeBlock block, LinkedList<CodeBlockReferenceImpl> blockRefQueue, 
    	boolean followIndirectFlows, TaskMonitor monitor) throws CancelledException {
    	
    	if (block == null) {
            return 0;
        }     
        
        CodeBlockModel m = block.getModel();
		if (!(m instanceof SimpleBlockModel))
			throw new IllegalArgumentException();	
		SimpleBlockModel model = (SimpleBlockModel) m;
		
        Address start = block.getMinAddress();
        if (start == null)
        	return 0;
        	
        int count = 0;
		Listing listing = model.getListing();
		Instruction instr = listing.getInstructionAt(start);
		
        // get the references from the symbol table.
        ReferenceManager refMgr = model.getProgram().getReferenceManager();
        Address[] entryPts = block.getStartAddresses();

		// Check references to all entry points - very special case to have more than one
    	for (int n = 0; n < entryPts.length; n++) {
     		ReferenceIterator iter = refMgr.getReferencesTo(entryPts[n]);
    		while (iter.hasNext()) {
    			Reference ref = iter.next();
    			RefType refType = ref.getReferenceType();
    			
    			if (monitor != null && monitor.isCancelled())
					throw new CancelledException();
    			
    			// Handle FlowType reference 
    			if (refType.isFlow()) {
    				queueDestReference(
    					blockRefQueue,
    					block, 
            			entryPts[n],
            			ref.getFromAddress(),
            			(FlowType)refType,
            			monitor);
            		++count;
    			}
    			
    			// Handle possible indirection
    			else if (followIndirectFlows && (instr != null || start.isExternalAddress())) {
        			int cnt = followIndirection(blockRefQueue, block, ref, monitor);
//        			if (cnt == 0) {
//        				// Could not resolve indirection - include ref as invalid flow
//        				queueDestReference(
//        					blockRefQueue,
//        					block, 
//                			entryPts[n],
//                			refs[i].getFromAddress(),
//                			FlowType.INVALID);
//                		cnt = 1;
//        			}
        			count += cnt;        
				}
    		}
    	}

        // Get single fall-from address for instruction block		
 		if (instr != null) {
 			Address fallAddr = instr.getFallFrom();
 			if (fallAddr != null) {
 				queueDestReference(
					blockRefQueue,
					block, 
        			start,
        			fallAddr,
        			RefType.FALL_THROUGH,
        			monitor);
        		++count;
 			}
 		}
        return count;
    }
 
    /**
     * Process a data reference for possible indirect sources.  Update block reference queue 
     * with indirect block references.
     * @param blockRefQueue the CodeBlockReference queue, may be null
     * @param destBlock reference/destination block
     * @param destRef possible pointer reference to destBlock (is not verified)
     * @param indirectFlowType reference type to assign to indirect references discovered
     * @param monitor task monitor which allows user to cancel operation.
     * @return number of references found, 0 if memRef does not correspond to a pointer.
     * @throws CancelledException if the monitor cancels the operation.
     */
    private static int followIndirection(LinkedList<CodeBlockReferenceImpl> blockRefQueue, CodeBlock destBlock, Reference destRef, TaskMonitor monitor) throws CancelledException {    	
		
		SimpleBlockModel model = (SimpleBlockModel)destBlock.getModel();
		Address addr = destRef.getFromAddress();
		Listing listing = model.getListing();
		Data data = listing.getDefinedDataContaining(addr);
		if (data == null)
			return 0;
			
    	int cnt = 0;
    	
// ?? Handle special cases - offset is 0 within array of pointers, or offset to pointer within array of structures
    	
    	int offset = (int)addr.subtract(data.getMinAddress());
    	Data primitive = data.getPrimitiveAt(offset);
    	if (primitive != null) {

			// Follow references to pointer - could have multiple references 			
			ReferenceIterator iter = primitive.getReferenceIteratorTo();
			while (iter.hasNext()) {
				Reference ref = iter.next();
				
				if (monitor.isCancelled())
					throw new CancelledException();
				
				RefType rt = ref.getReferenceType();			
				if (rt != RefType.INDIRECTION && rt != RefType.READ)
					continue;
				
				Address fromAddr = ref.getFromAddress();
				Instruction instr = listing.getInstructionAt(fromAddr);
								
				if (instr == null)
					continue;
				
				if (rt == RefType.READ && !instr.getFlowType().isComputed())
					continue;

				queueDestReference(blockRefQueue, destBlock, destRef.getToAddress(), fromAddr,
				            instr.getFlowType().isCall() ? RefType.COMPUTED_CALL : RefType.COMPUTED_JUMP, monitor);
				++cnt;
			}  			
    	}
    	return cnt;
    }
    
    /**
     * Create a new block reference and add it to the queue.
     * @param blockRefQueue the CodeBlockReference queue, may be null
     * @param destBlock reference/destination block
     * @param toAddr reference destination address
     * @param fromAddr reference source address
     * @param flowType reference flow type
     * @param monitor task monitor which allows user to cancel operation.
     */
    private static void queueDestReference(LinkedList<CodeBlockReferenceImpl> blockRefQueue, CodeBlock destBlock, 
    	Address toAddr, Address fromAddr, FlowType flowType, TaskMonitor monitor) {
    	
    	if (blockRefQueue == null)
    		return;
    	
    	blockRefQueue.add(new CodeBlockReferenceImpl(null, destBlock, flowType, toAddr, fromAddr));
    	
    }
}
