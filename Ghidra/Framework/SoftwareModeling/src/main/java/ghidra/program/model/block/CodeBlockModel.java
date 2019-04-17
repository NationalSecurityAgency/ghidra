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
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * An implementation of a CodeBlockModel will produce CodeBlocks
 * based on some algorithm.
 */
public interface CodeBlockModel {

	public static final CodeBlock[] emptyBlockArray = new CodeBlock[0];
	
	/**
	 * Returns the model name.
	 * @return the model name
	 */
	public String getName();
	
    /**
     * Get the code block with a starting address (i.e., entry-point) of addr.
     * @param addr starting address of a codeblock.
     * @param monitor task monitor which allows user to cancel operation.
     * @return null if there is no codeblock starting at the address.
     * @throws CancelledException if the monitor cancels the operation.
     */
    public CodeBlock getCodeBlockAt(Address addr, TaskMonitor monitor) throws CancelledException;

    /**
     * Get the first code block that contains the given address.
     * @param addr    address to find a containing block.
     * @param monitor task monitor which allows user to cancel operation.
     * @return a block that contains the address, or null otherwise.
     * @throws CancelledException if the monitor cancels the operation.
     */
    public CodeBlock getFirstCodeBlockContaining(Address addr, TaskMonitor monitor) throws CancelledException;

    /**
     * Get all the code blocks containing the address.
     * @param addr   address to find a containing block.
     * @param monitor task monitor which allows user to cancel operation.
     * @return an array of blocks that contains the address, null otherwise.
     * @throws CancelledException if the monitor cancels the operation.
     */
    public CodeBlock[] getCodeBlocksContaining(Address addr, TaskMonitor monitor) throws CancelledException;

    /**
     * Get an iterator over the code blocks in the entire program.
     * @param monitor task monitor which allows user to cancel operation.
     * @throws CancelledException if the monitor cancels the operation.
     */
    public CodeBlockIterator getCodeBlocks(TaskMonitor monitor) throws CancelledException;

    /**
     * Get an iterator over code blocks which overlap the specified address set.
     * @param addrSet   an address set within program
     * @param monitor task monitor which allows user to cancel operation.
     * @throws CancelledException if the monitor cancels the operation.
     */
    public CodeBlockIterator getCodeBlocksContaining(AddressSetView addrSet, TaskMonitor monitor) throws CancelledException;

    /**
     * Get an iterator over the source flows into the block.
     * @param block the block to get the destination flows for.
     * @param monitor task monitor which allows user to cancel operation.
     * @throws CancelledException if the monitor cancels the operation.
     */
    public CodeBlockReferenceIterator getSources(CodeBlock block, TaskMonitor monitor) throws CancelledException;
    
    /**
     * Get the number of source flows into the block.
     * @param block the code blocks to get the destination flows for.
     * @param monitor task monitor which allows user to cancel operation.
     * @throws CancelledException if the monitor cancels the operation.
     */
    public int getNumSources(CodeBlock block, TaskMonitor monitor) throws CancelledException;

    /**
     * Get an iterator over the destination flows out of the block.
     * @param block the block to get the destination flows for.
     * @param monitor task monitor which allows user to cancel operation.
     * @throws CancelledException if the monitor cancels the operation.
     */
    public CodeBlockReferenceIterator getDestinations(CodeBlock block, TaskMonitor monitor) throws CancelledException;

    /**
     * Get the number of destination flows out of the block.
     * @param block the code blocks to get the destination flows for.
     * @param monitor task monitor which allows user to cancel operation.
     * @throws CancelledException if the monitor cancels the operation.
     */
    public int getNumDestinations(CodeBlock block, TaskMonitor monitor) throws CancelledException;

	/**
     * Get the basic block model used by this model.
     */
    public CodeBlockModel getBasicBlockModel();
    
    /**
     * Returns true if externals are handled by the model,
     * false if externals are ignored.  When handled, externals
     * are represented by an ExtCodeBlockImpl.
     */
    public boolean externalsIncluded();

    /**
     * Return in general how things flow out of this node.
     * If there are any abnormal ways to flow out of this node,
     * (ie: jump, call, etc...) then the flow type of the node
     * takes on that type.
     * If there are multiple unique ways out of the node, then we
     * should return FlowType.UNKNOWN (or FlowType.MULTIFLOW ?).
     * Fallthrough is returned if that is the only way out.
     * @return flow type of this node
     */
    public FlowType getFlowType(CodeBlock block);

    /**
     * Get a name for this block.
     * @return usually the label at the start address of the block
     *    however the model can choose any name it wants for its blocks.
     */
    public String getName(CodeBlock block);
    
    /**
     * Returns the program object associated with this CodeBlockModel instance.
     * @return program associated with this CodeBlockModel.
     */
    public Program getProgram();

	/**
	 * Return true if this model allows overlapping of address sets for
	 * the blocks it returns.
	 * @return true if this model allows overlapping of address sets for
	 *         the blocks it returns.
	 *         This implies that getBlocksContaining() can return more than one block.
	 *         false implies that getBlocksContaining() will return at most one block.
	 */
	public boolean allowsBlockOverlap();
}
