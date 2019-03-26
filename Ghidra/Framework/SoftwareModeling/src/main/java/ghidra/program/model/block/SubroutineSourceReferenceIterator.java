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
 * SubroutineSourceReferenceIterator is a unidirectional iterator over 
 * the source <CODE>CodeBlockReference</CODE>s for a CodeBlock.
 */
public class SubroutineSourceReferenceIterator implements CodeBlockReferenceIterator {
    
    // queue of discovered source block references
	private LinkedList<CodeBlockReference> blockRefQueue = new LinkedList<CodeBlockReference>();

	private TaskMonitor monitor;
	
    /**
     *  Construct an Iterator over Source blocks for a CodeBlock.
     *
     * @param block block to get destination blocks for.  This should be a
     * subroutine obtained from SubroutineBlockModel.
     * @param monitor task monitor which allows user to cancel operation.
     * @throws CancelledException if the monitor cancels the operation.
     */
    public SubroutineSourceReferenceIterator(CodeBlock block, TaskMonitor monitor) throws CancelledException {
        this.monitor = monitor;
		getSources(block, blockRefQueue, monitor);
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
     * @param monitor task monitor which allows user to cancel operation.
     * @throws CancelledException if the monitor cancels the operation.
     */
    public static int getNumSources(CodeBlock block, TaskMonitor monitor) throws CancelledException {
    	return getSources(block, null, monitor);
    }
    
    /**
     * Count and queue all source references flowing from this subroutine (block).
     * All Calls to this block, and all external FlowType block references
     * to this block are counted.
     * 
     * @param block code block to get the number of source references to.
     * @param blockRefQueue the CodeBlockReference queue, may be null
     * @param monitor task monitor which allows user to cancel operation.
     * @throws CancelledException if the monitor cancels the operation.
     */
    private static int getSources(CodeBlock block, List<CodeBlockReference> blockRefQueue, TaskMonitor monitor) throws CancelledException {
    	
    	if (block == null || block.getMinAddress() == null) {
            return 0;
        }

        int count = 0;

		CodeBlockModel model = block.getModel();

        // Iterate over all basic blocks within specified block
        CodeBlockIterator bblockIter = (model.getBasicBlockModel()).getCodeBlocksContaining(block, monitor);
        while (bblockIter.hasNext()) {

			// Get next basic block
			CodeBlock bblock = bblockIter.next();
			
			// Get basic block sources
			CodeBlockReferenceIterator bbSrcIter = bblock.getSources(monitor);
			while (bbSrcIter.hasNext()) {
				CodeBlockReference bbSrcRef = bbSrcIter.next();
				FlowType refFlowType = bbSrcRef.getFlowType();
				
				if (refFlowType.isCall()) 
                {
					// Add all forward CALL references to queue
					count += queueSrcReferences(blockRefQueue,
						block, 
						bbSrcRef.getReference(), 
						bbSrcRef.getReferent(), 
						refFlowType,
						monitor);
                }
                else if (refFlowType.isJump() || refFlowType.isFallthrough()) 
                {		
                	// Add external JUMP and FALL-THROUGH references to queue
                	Address srcAddr = bbSrcRef.getReferent();
                	if (!block.contains(srcAddr) && model.getFirstCodeBlockContaining(srcAddr, monitor) != null) {
                		count += queueSrcReferences(blockRefQueue, 
                			block,
                			bbSrcRef.getReference(), 
                			srcAddr, 
                			refFlowType,
                			monitor);
                    }
                }
			}			
        }
		return count;
    }
    
    /**
     * Create source block reference and add it to the blockRefQueue if block
     * is found at specified srcAddr.  A valid block must exist at the srcAddr
     * for a reference to be added and/or counted.
     * @param blockRefQueue the CodeBlockReference queue, may be null
     * @param destBlock the source block associated with the CodeBlockReference(s)
     * @param destAddr destination address
     * @param srcAddr source address
     * @param flowType the flow type to be associated with reference.
     * @param monitor task monitor which allows user to cancel operation.
     * @return the number of source references
     * @throws CancelledException if the monitor cancels the operation.
     */
    private static int queueSrcReferences(List<CodeBlockReference> blockRefQueue, CodeBlock destBlock, 
    	Address destAddr, Address srcAddr, FlowType flowType, TaskMonitor monitor) 
    	throws CancelledException {
    	
    	CodeBlockModel model =  destBlock.getModel();
    	if (model.allowsBlockOverlap()) {
    		CodeBlock[] srcBlocks = model.getCodeBlocksContaining(srcAddr, monitor);
    		int cnt = srcBlocks.length;
    		if (blockRefQueue != null) {
    			for (int i = 0; i < cnt; i++) {
// ?? Non-block references are lost since they don't have a corresponding code block     			
	        		CodeBlockReference blockRef = new CodeBlockReferenceImpl(
	        										srcBlocks[i], 
	        										destBlock, 
	        										flowType, 
	        										destAddr, 
	        										srcAddr);
					blockRefQueue.add(blockRef);
	        	}
    		}
    		if (cnt != 0) {
    			return cnt;
    		}
    	}
    	
    	if (blockRefQueue != null) {
			CodeBlockReference blockRef = new CodeBlockReferenceImpl(
												null,
												destBlock, 
												flowType, 
												destAddr, 
												srcAddr);
	
			blockRefQueue.add(blockRef);
    	}
    	return 1;
    }
    
}
