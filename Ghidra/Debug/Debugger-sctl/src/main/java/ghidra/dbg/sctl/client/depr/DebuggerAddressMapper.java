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
package ghidra.dbg.sctl.client.depr;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;

/**
 * A bijection of debugger addresses to offsets
 * 
 * <p>
 * Some debuggers and/or debugging protocols map multiple address spaces into a single offset space.
 * This interface provides the conversion functions between the two. The offset is typically used to
 * communicate to the debugger. The address objects are used by Ghidra identify a location within
 * the target's memory model.
 */
public interface DebuggerAddressMapper {

	/**
	 * Convert an offset to an address
	 * 
	 * @param offset the offset
	 * @return the address
	 */
	public Address mapOffsetToAddress(long offset);

	/**
	 * Convert an address to an offset
	 * 
	 * @param address the address
	 * @return the offset
	 */
	public long mapAddressToOffset(Address address);

	/**
	 * Get the factory to create addresses in the target's memory model
	 * 
	 * @return the factory
	 */
	public AddressFactory getAddressFactory();
}
