/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.LinkedList;
import java.util.List;

/**
 * SubroutineDestReferenceIterator is a unidirectional iterator over 
 * the destination <CODE>CodeBlockReference</CODE>s for a CodeBlock.
 */
public class SubroutineDestReferenceIterator implements CodeBlockReferenceIterator {

    // queue of discovered destination block references
	private LinkedList<CodeBlockReference> blockRefQueue = new LinkedList<CodeBlockReference>();
	
	private TaskMonitor monitor;

    /**
     * Construct an Iterator over Destination blocks for a CodeBlock.
     * External references will be ignored.
     * @param block block to get destination blocks for.  This should be a
     * subroutine obtained from PartitionCodeSubModel.
     * @param monitor task monitor which allows user to cancel operation.
     * @throws CancelledException if the monitor cancels the operation.
     */
    public SubroutineDestReferenceIterator(CodeBlock block, TaskMonitor monitor) throws CancelledException {
    	this.monitor = monitor;
		getDestinations(block, blockRefQueue, monitor);
    }
    
    /**
     * @see ghidra.program.model.block.CodeBlockReferenceIterator#next()
     */
    public CodeBlockReference next() throws CancelledException {
    	monitor.checkCanceled();
    	return blockRefQueue.isEmpty() ? null : blockRefQueue.removeFirst();
    }

    /**
     * @see ghidra.program.model.block.CodeBlockReferenceIterator#hasNext()
     */
    public boolean hasNext() throws CancelledException {
    	monitor.checkCanceled();
		return !blockRefQueue.isEmpty();
    }
    
    /**
     * Get number of destination references flowing out of this subroutine (block).
     * All Calls from this block, and all external FlowType block references
     * from this block are counted.
     * 
     * @param block code block to get the number of destination references from.
     * @param monitor task monitor
     */
    public static int getNumDestinations(CodeBlock block, TaskMonitor monitor) throws CancelledException {
    	return getDestinations(block, null, monitor);
    }
    
    /**
     * Count and queue all destination references flowing out of this subroutine (block).
     * All Calls from this block, and all external FlowType block references
     * from this block are counted.
     * 
     * @param block code block to get the number of destination references from.
     * @param blockRefQueue the CodeBlockReference queue, may be null
     * @param includeExternals external references will be included if true
     * @param monitor task monitor
     */
    private static int getDestinations(CodeBlock block, List<CodeBlockReference> blockRefQueue, TaskMonitor monitor) throws CancelledException {
    	
    	if (block == null || block.getMinAddress() == null) {
            return 0;
        }

        int count = 0;

		CodeBlockModel model = block.getModel();
		boolean includeExternals = model.externalsIncluded();

        // Iterate over all basic blocks within specified block
        CodeBlockIterator bblockIter = (model.getBasicBlockModel()).getCodeBlocksContaining(block, monitor);
        while (bblockIter.hasNext()) {

			// Get next basic block
			CodeBlock bblock = bblockIter.next();
			
			// Get basic block destinations
			CodeBlockReferenceIterator bbDestIter = bblock.getDestinations(monitor);
			while (bbDestIter.hasNext()) {
				CodeBlockReference bbDestRef = bbDestIter.next();
				FlowType refFlowType = bbDestRef.getFlowType();
				Address destAddr = bbDestRef.getReference();
				boolean addBlockRef = false;
				if (destAddr.isExternalAddress()) {
					if (includeExternals) {
						// Add all forward external references to queue if includeExternals
						addBlockRef = true;
					}
				}
				else if (refFlowType.isCall()) {
					// Add all forward CALL references to queue
					addBlockRef = true;
                }
                else if (refFlowType.isJump() || refFlowType.isFallthrough()) {		
                	// Add forward external JUMP and FALL-THROUGH references to queue
                	if (!block.contains(destAddr)) {
                		addBlockRef = true;
                    }
                }
				if (addBlockRef) {
					queueDestReferences(blockRefQueue,
										block, 
										bbDestRef.getReferent(), 
										destAddr, 
										refFlowType);
					count++;
				}
			}			
        }
		return count;
    }
    
    /**
     * Create destination block reference(s) and add to the blockRefQueue if not null.
     * A valid CodeBlock must exist at the destAddr for a reference to be added and/or counted.
     * @param blockRefQueue the CodeBlockReference queue, may be null
     * @param srcBlock the source block associated with the CodeBlockReference(s)
     * @param srcAddr source address
     * @param destAddr destination address
     * @param flowType the flow type to be associated with reference.
     * @return the number of destination references
     */
    private static void queueDestReferences(List<CodeBlockReference> blockRefQueue, CodeBlock srcBlock, Address srcAddr, Address destAddr, FlowType flowType) {
    	if (blockRefQueue != null) {			
	        CodeBlockReference blockRef = new CodeBlockReferenceImpl(
	        										srcBlock,
	        										null,
	        										flowType, 
	        										destAddr, 
	        										srcAddr);
			blockRefQueue.add(blockRef);
    	}
    }
    
}
