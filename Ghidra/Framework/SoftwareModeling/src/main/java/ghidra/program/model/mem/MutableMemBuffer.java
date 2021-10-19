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
package ghidra.program.model.mem;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;

/**
 * The MutableMemBuffer interface facilitates repositioning of a MemBuffer object.
 */
public interface MutableMemBuffer extends MemBuffer {

	/**
	 * Advance the Address pointer.
	 *
	 * @param displacement the amount to adjust the pointer by.
	 * @throws AddressOverflowException if displacement would cause the buffer position to wrap.
	 */
	public void advance(int displacement) throws AddressOverflowException;

	/**
	 * Sets the Address to which offset of 0 points to.
	 *
	 * @param addr the new base Address.
	 */
	public void setPosition(Address addr);

	/**
	 * Create a cloned copy of this MutableMemBuffer
	 * 
	 * @return new cloned instance of this buffer object
	 */
	public MutableMemBuffer clone();
}
