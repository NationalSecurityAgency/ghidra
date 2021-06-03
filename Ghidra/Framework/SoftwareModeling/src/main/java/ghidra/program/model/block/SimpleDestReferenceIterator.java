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
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.LinkedList;

/**
 *  This iterator is implemented by getting the flows from the instruction
 *  and iterating over those flows (plus the fallthrough).  This is probably
 *  not the most efficient method.  An linked-list of references has to be created each
 *  time we want to get the destinations from a block.
 */
public class SimpleDestReferenceIterator implements CodeBlockReferenceIterator {	
	
    // queue of discovered destination block references
	private LinkedList<CodeBlockReferenceImpl> blockRefQueue = new LinkedList<CodeBlockReferenceImpl>();
	private TaskMonitor monitor;

    /**
     * Construct an Iterator over Destination blocks for a CodeBlock.
     * External references are ignored.
     * @param block block to get destination blocks for.  This should be a
     * block obtained from SimpleBlockModel.
     * @param followIndirectFlows indirect references will only be included if true
     * @param monitor task monitor which allows user to cancel operation.
     * @throws CancelledException if the monitor cancels the operation.
     */
    public SimpleDestReferenceIterator(CodeBlock block, boolean followIndirectFlows, TaskMonitor monitor) throws CancelledException {
    	this.monitor = monitor;
		getDestinations(block, blockRefQueue, followIndirectFlows, monitor);
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
     * Get number of destination references flowing out of this block.
     * All Calls from this block, and all external FlowType block references
     * from this block are ignored.
     * 
     * @param block code block to get the number of destination references from.
     * @param followIndirectFlows indirect references will only be included if true
     * @param monitor task monitor which allows user to cancel operation.
     * @throws CancelledException if the monitor cancels the operation.
     * @deprecated this method should be avoided since it repeats the work of the iterator
     */
	@Deprecated
    public static int getNumDestinations(CodeBlock block, boolean followIndirectFlows, TaskMonitor monitor) throws CancelledException {
    	return getDestinations(block, null, followIndirectFlows, monitor);
    }
    
    /**
     * Count and queue all destination references flowing out of this block.
     * All Calls from this block, and all external FlowType block references
     * from this block are counted.
     * 
     * @param block code block to get the number of destination references from.
     * @param blockRefQueue the CodeBlockReference queue, may be null
     * @param followIndirectFlows indirect references will only be included if true
     * @param includeExternals externals will be included if true
     * @param monitor task monitor which allows user to cancel operation.
     * @throws CancelledException if the monitor cancels the operation.
     */
    private static int getDestinations(CodeBlock block, LinkedList<CodeBlockReferenceImpl> blockRefQueue, 
    	boolean followIndirectFlows, TaskMonitor monitor) throws CancelledException {
    
    	if (block == null)
            return 0;

		CodeBlockModel m = block.getModel().getBasicBlockModel();
		if (!(m instanceof SimpleBlockModel))
			throw new IllegalArgumentException();	
		SimpleBlockModel model = (SimpleBlockModel)m;
		boolean includeExternals = model.externalsIncluded();
		
		Address start = block.getMinAddress();
		Address end = block.getMaxAddress();
		if (start == null || start.isExternalAddress())
			return 0;
			
		int count = 0;
		Listing listing = model.getListing();
		ReferenceIterator refIter = model.getProgram().getReferenceManager().getReferenceIterator(start);
		Instruction instr = null;
		while (refIter.hasNext()) {

        	if (monitor != null && monitor.isCancelled())
				throw new CancelledException();
				
        	Reference ref = refIter.next();
			Address fromAddr = ref.getFromAddress();
			if (fromAddr.compareTo(end) > 0)
				break;

    		// Examine all flow-type references
    		RefType refType = ref.getReferenceType();
    		if (!(refType.isFlow()))
    			continue;
    		
    		// Handle possible indirection
    		// Indirect flow should be to a data pointer which references code.
    		if (refType == RefType.INDIRECTION) {
				Instruction destInstr = listing.getInstructionContaining(ref.getToAddress());
				int cnt = 0;
    			if (destInstr == null && followIndirectFlows) {
    				if (instr == null || !instr.getMinAddress().equals(fromAddr)) {
						instr = listing.getInstructionAt(fromAddr);
					}
        			cnt = followIndirection(blockRefQueue, includeExternals, block, ref, 
						instr.getFlowType().isCall() ? RefType.COMPUTED_CALL : RefType.COMPUTED_JUMP,
						monitor);
    			}
    			if (cnt == 0) {
    				// Improper indirection - add original reference
    				queueDestReference(
    					blockRefQueue,
    					block, 
            			fromAddr,
            			ref.getToAddress(),
						RefType.INDIRECTION);
            		cnt = 1;
    			}
    			count += cnt;        			
    		}
    		
    		// Handle other FlowType reference
    		else {
    			// Add FlowType references
    			queueDestReference(
    				blockRefQueue, 
    				block,
        			fromAddr,
        			ref.getToAddress(),
        			(FlowType)refType);
        		++count;
    		}
        }
		
		// Check for implied indirection if no destinations were found
		if (followIndirectFlows && count == 0 && block.getFlowType().isComputed()) {
			
			instr = listing.getInstructionContaining(block.getMaxAddress());
	        if (instr != null) {
	        	
	        	// search backwards until a non-delay slot instruction is found
	        	while (instr.isInDelaySlot()) {
		        	Address fallFrom = instr.getFallFrom();
		        	if (fallFrom == null) {
		        	    Msg.warn(SimpleDestReferenceIterator.class, "WARNING: Invalid delay slot instruction found at " + instr.getMinAddress());
		        		break;
		        	}
		        	instr = listing.getInstructionContaining(fallFrom);
		        }
	        	for (Reference ref : instr.getReferencesFrom()) {
	        		count += followIndirection(blockRefQueue, includeExternals, block, ref, 
							instr.getFlowType().isCall() ? RefType.COMPUTED_CALL : RefType.COMPUTED_JUMP,
							monitor);
	        	}
	        }
			
		}
        
        // Check for single fall-through destination
        instr = listing.getInstructionContaining(end);
        if (instr != null) {
        	instr = instr.getNext();
        	if (instr != null) {
        		Address addr = instr.getFallFrom();
        		if (addr != null && addr.compareTo(end) <= 0) {
					queueDestReference(
						blockRefQueue,
						block,
						addr,
						instr.getMinAddress(),
						RefType.FALL_THROUGH);
					++count;
        		}
	        }
        }

		return count;
    }
 
    /**
     * Process a data reference for possible indirection.  Update block reference queue 
     * with indirect block references.
     * @param blockRefQueue the CodeBlockReference queue, may be null
     * @param srcBlock referent/source block
     * @param srcRef possible indirect reference from srcBlock (is not verified)
     * @param indirectFlowType reference type to assign to indirect references discovered
     * @param includeExternals externals will be included if true
     * @param monitor task monitor which allows user to cancel operation.
     * @return number of references found, 0 if memRef does not correspond to a pointer.
     * @throws CancelledException if the monitor cancels the operation.
     */
    private static int followIndirection(LinkedList<CodeBlockReferenceImpl> blockRefQueue, boolean includeExternals, CodeBlock srcBlock, 
    	Reference srcRef, FlowType indirectFlowType, TaskMonitor monitor) 
    	throws CancelledException {	
		
		SimpleBlockModel model = (SimpleBlockModel)srcBlock.getModel();
		Address addr = srcRef.getToAddress();
		Listing listing = model.getListing();
		Data data = listing.getDefinedDataContaining(addr);
		if (data == null)
			return 0;
			
    	int cnt = 0;
    	
// ?? Handle special cases - offset is 0 within array of pointers, or offset to pointer within array of structures
    	
    	int offset = (int)addr.subtract(data.getMinAddress());
    	Data primitive = data.getPrimitiveAt(offset);
    	if (primitive != null) {

			// Follow pointer - could have multiple references 			
			Reference refs[] = primitive.getReferencesFrom();
			for (int i = 0; i < refs.length; i++) {
				
				monitor.checkCanceled();
				
				CodeBlock destBlock = null;
				
				Address toAddr = refs[i].getToAddress();
				if (toAddr.isMemoryAddress()) {
				
					CodeUnit cu = listing.getCodeUnitAt(toAddr);
						
					if (cu != null) {
						
						// Handle instruction reference
						if (cu instanceof Instruction) {
							if (blockRefQueue != null) {
								destBlock = model.getFirstCodeBlockContaining(toAddr, monitor);
							}				
						}
						
						// Skip indirect defined-data destinations
						else if ((cu instanceof Data) && ((Data)cu).isDefined()) {
							continue;
						}
					}
				}
				else if (toAddr.isExternalAddress()) {
					if (!includeExternals) {
						continue;
					}
					if (blockRefQueue != null) {
						destBlock = model.getFirstCodeBlockContaining(toAddr, monitor);
					}	
				}
					
				// Queue block reference
				if (blockRefQueue != null) {
					
					if (destBlock == null) {						
						// means that there will not be a good destination block there,
				        //    make an invalid destination block
				        //  TODO: This might not be the right thing to do.  Return a
				        //        codeBlock that really isn't there, but should be if
				        //        there were valid instructions.  If you got it's start
				        //        address then got the block starting at from the model,
				        //        you would get null, so maybe the model should be changed
				        //        to return a block at this address....

						// Create artificial block at bad destination
						destBlock = model.createSimpleDataBlock(toAddr, toAddr);
					}

					blockRefQueue.add(
						new CodeBlockReferenceImpl(
							srcBlock,
							destBlock,
							indirectFlowType,
							toAddr,
							srcRef.getFromAddress()));
				}
				++cnt;
				
			}  			
    	}
    	return cnt;
    }
    
    /**
     * Create a new block reference and add it to the queue.
     * @param blockRefQueue the CodeBlockReference queue, may be null
     * @param srcBlock referent/source block
     * @param fromAddr reference source address
     * @param toAddr reference destination address
     * @param flowType reference flow type
     * @param monitor task monitor which allows user to cancel operation.
     * @throws CancelledException if the monitor cancels the operation.
     */
    private static void queueDestReference(LinkedList<CodeBlockReferenceImpl> blockRefQueue, CodeBlock srcBlock, 
    	Address fromAddr, Address toAddr, FlowType flowType) {
    	
    	if (blockRefQueue == null)
    		return;
    	
    	// create a Reference with the destination block uninitialized
    	blockRefQueue.add(
			new CodeBlockReferenceImpl(srcBlock, null, flowType, toAddr, fromAddr));
    	
    }		
					
}
