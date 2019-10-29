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
import ghidra.program.model.symbol.RefType;

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
	 * Get the primary overriding reference address of {@link RefType} {@code type} from 
	 * the current instruction
	 * @param type type of reference
	 * @return call reference address or null
	 */
	Address getOverridingReference(RefType type);

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

	/**
	 * Register that a call override has been applied at the current instruction.
	 */
	void setCallOverrideRefApplied();

	/**
	 * Returns a boolean indicating whether a call override has been applied at the current instruction
	 * @return has call override been applied
	 */
	boolean isCallOverrideRefApplied();

	/**
	 * Register that a jump override has been applied at the current instruction
	 */
	void setJumpOverrideRefApplied();

	/**
	 * Returns a boolean indicating whether a jump override has been applied at the current instruction
	 * @return has jump override been applied
	 */
	boolean isJumpOverrideRefApplied();

	/**
	 * Register that a callother call override has been applied at the current instruction
	 */
	void setCallOtherCallOverrideRefApplied();

	/**
	 * Returns a boolean indicating whether a callother call override has been applied at the current
	 * instruction
	 * @return has callother call override been applied
	 */
	boolean isCallOtherCallOverrideRefApplied();

	/**
	 * Register that a callother jump override has been applied at the current instruction
	 */
	void setCallOtherJumpOverrideRefApplied();

	/**
	 * Returns a boolean indicating whether a callother jump override has been applied at the current
	 * instruction
	 * @return has callother jump override been applied
	 */
	boolean isCallOtherJumpOverrideApplied();

	/**
	 * Returns a boolean indicating whether there are any primary overriding references at the current 
	 * instruction
	 * @return are there primary overriding references
	 */
	boolean hasPotentialOverride();

	/**
	 * 
	 * Get the primary call reference address from the current instruction
	 * @return call reference address or null
	*/
	@Deprecated
	Address getPrimaryCallReference();

}
