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
package ghidra.program.model.symbol;

import ghidra.program.model.address.Address;

/**
 * Interface to define an equate reference. Equate references consist of an 
 * address and an operand index.
 */
public interface EquateReference {

	/**
	 * Returns the address associated with this reference.
	 */
	Address getAddress();
	
	/**
	 * Returns the opcode index for the instruction located at this
	 * references address, or -1 if .
	 */
	short getOpIndex();
	
	/**
	 * Returns the dynamic Hash value associated with the referenced constant varnode.
	 * A value of zero (0) indicates not applicable.
	 * @see ghidra.program.model.pcode.DynamicHash
	 */
	long getDynamicHashValue();
}
