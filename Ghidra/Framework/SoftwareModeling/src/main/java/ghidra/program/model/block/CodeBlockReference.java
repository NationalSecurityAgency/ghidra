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

/**
 * A CodeBlockReference represents the flow from one CodeBlock to another. Flow
 * consists of: 
 * <ul>
 * <li>The source and destination CodeBlocks</li>
 * <li>The Type of flow (JMP, CALL, Fallthrough, etc...</li>
 * <li>The referent - the instruction's address in the source block that causes
 * the flow </li>
 * <li>The reference - the address in the destination block that is flowed to.
 * </li>
 * </ul>
 *
 */
public interface CodeBlockReference {

    /**
     * Returns the Source Block address.
     * The source address should only occur in one block.
     * @return the Source Block address
     */
    public Address getSourceAddress();

    /**
     * Returns the Destination Block address.
     * The destination address should only occur in one block.
     * @return the Destination Block address
     */
    public Address getDestinationAddress();

    /**
     * Returns the type of flow from the Source to the Destination CodeBlock.
     * @return the type of flow
     */
    public FlowType getFlowType();

    /**
     * Returns the address in the Destination block that is referenced by the Source block.
     * @return the address in the Destination block that is referenced by the Source block
     */
    public Address getReference();

    /**
     * Returns the address of the instruction in the Source Block that refers to the Destination block.
     * @return the address of the instruction in the Source Block that refers to the Destination block
     */ 
    public Address getReferent();

    /**
     * Returns the Destination CodeBlock.
     * @return the Destination CodeBlock
     */ 
    public CodeBlock getDestinationBlock();

    /** 
     * Returns the Source CodeBlock.
     * @return the Source CodeBlock
     */
    public CodeBlock getSourceBlock();
}
