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
package ghidra.program.model.pcode;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.listing.FlowOverride;

public interface PcodeOverride {
	
	/**
	 * @return current instruction address
	 */
	Address getInstructionStart();

	/**
	 * Get the flow override which may have been applied
	 * to the current instruction.
	 * @return flow override or null
	 */
	FlowOverride getFlowOverride();

	/**
	 * Get the primary call reference address from the current instruction
	 * @return call reference address or null
	 */
	Address getPrimaryCallReference();

	/**
	 * Get the fall-through override address which may have been 
	 * applied to the current instruction.
	 * @return fall-through override address or null
	 */
	Address getFallThroughOverride();
	
	/**
     * Returns the call-fixup for a specified call destination.
     * @param callDestAddr call destination address.  This address is used to 
     * identify a function which may have been tagged with a CallFixup.  
     * @return true if call destination function has been tagged with a call-fixup
     */
	boolean hasCallFixup(Address callDestAddr);
	
	/**
     * Returns the call-fixup for a specified call destination.
     * If the destination function has not be tagged or was tagged 
     * with an unknown CallFixup name this method will return null.
     * @param callDestAddr call destination address.  This address is used to 
     * identify a function which may have been tagged with a CallFixup.  
     * @return call fixup object or null
     */
	InjectPayload getCallFixup(Address callDestAddr);

}
