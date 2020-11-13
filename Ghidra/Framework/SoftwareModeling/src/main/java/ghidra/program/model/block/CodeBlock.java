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
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * CodeBlock represents some group of Instructions/Data.  Each block
 * has some set of source blocks that flow into it and some
 * set of destination blocks that flow out of it.  A BlockModel
 * is used to produce CodeBlocks.  Each model produces blocks
 * based on its interpretation of Instruction/Data grouping and flow
 * between those groups.
 */


public interface CodeBlock extends AddressSetView {
    
    /** 
     * Return the first start address of the CodeBlock.
     * Depending on the model used to generate the CodeBlock,
     * there may be multiple entry points to the block.  This will
     * return the first start address for the block.  It should
     * always return the same address for a given block if there
     * is more than one entry point.
     *
     * @return the first start address of the block.
     */
    public Address getFirstStartAddress();
    
    /** 
     * Get all the entry points to this block.  Depending on the
     * model, there may be more than one entry point.
     * Entry points will be returned in natural sorted order.
     *
     * @return an array of entry points to this block.
     * a zero length array if there are no entry points.
     */
    public Address[] getStartAddresses();
    
    /** 
     * Return the name of the block.
     * 
     * @return name of block,
     *  normally the symbol at the starting address
     */
    public String getName();
    
    /**
     * Return, in theory, how things flow out of this node.
     * If there are any abnormal ways to flow out of this node,
     * (ie: jump, call, etc...) then the flow type of the node
     * takes on that type.
     * If there are multiple unique ways out of the node, then we
     * should return FlowType.UNKNOWN.
     * Fallthrough is returned if that is the only way out.
     *
     * @return flow type of this node
     */
    public FlowType getFlowType();
    
    /**
     * Get the number of CodeBlocks that flow into this CodeBlock.
     * Note that this is almost as much work as getting the actual source references.
     * @param monitor task monitor which allows user to cancel operation.
     * @return number of source CodeBlocks.
     * @throws CancelledException if the monitor cancels the operation.
     * @see #getSources(ghidra.util.task.TaskMonitor)
     */
    public int getNumSources(TaskMonitor monitor) throws CancelledException;
    
    /**
     * Get an Iterator over the CodeBlocks that flow into this CodeBlock.
     * @param monitor task monitor which allows user to cancel operation.
     * @return An iterator over CodeBlocks referencing this Block.
     * @throws CancelledException if the monitor cancels the operation.
     */
    public CodeBlockReferenceIterator getSources(TaskMonitor monitor) throws CancelledException;
    
    /**
     * Get the number of CodeBlocks this block flows to.
     * Note that this is almost as much work as getting the actual destination references.
     * @param monitor task monitor which allows user to cancel operation.
     * @return number of destination CodeBlocks.
     * @throws CancelledException if the monitor cancels the operation.
     * @see #getDestinations(ghidra.util.task.TaskMonitor)
     */
    public int getNumDestinations(TaskMonitor monitor) throws CancelledException;
    
    /**
     * Get an Iterator over the CodeBlocks that are flowed to from this
     * CodeBlock.
     * @param monitor task monitor which allows user to cancel operation.
     * @return An iterator over CodeBlocks referred to by this Block.
     * @throws CancelledException if the monitor cancels the operation.
     */
    public CodeBlockReferenceIterator getDestinations(TaskMonitor monitor) throws CancelledException;
    
    /**
     * Get the model instance which was used to generate this block.
     * @return the model used to build this CodeBlock
     */
    public CodeBlockModel getModel();
}
