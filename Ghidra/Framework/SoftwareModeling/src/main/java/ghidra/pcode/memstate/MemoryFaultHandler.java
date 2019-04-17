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
package ghidra.pcode.memstate;

import ghidra.program.model.address.Address;

public interface MemoryFaultHandler {

	/**
	 * An attempt has been made to read uninitialized memory at the 
	 * specified address.  
	 * @param address
	 * @param size
	 * @param buf
	 * @param bufOffset
	 * @return true if data should be treated as initialized
	 */
	boolean uninitializedRead(Address address, int size, byte[] buf, int bufOffset);

	/**
	 * Unable to translate the specified address 
	 * @param address address which failed to be translated
	 * @param write true if memory operation was a write vs. read
	 * @return true if fault was handled
	 */
	boolean unknownAddress(Address address, boolean write);

}
