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
package ghidra.trace.model.listing;

import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.memory.TraceMemoryState;

/**
 * TODO
 * 
 * RULE: any defined code units (instruction or defined data) must be wholly-contained within a
 * {@link TraceMemoryState#KNOWN} portion of memory for the given snap.
 */
public interface TraceCodeSpace extends TraceCodeOperations {

	/**
	 * Get the address space of this code space
	 * 
	 * @return the address space
	 */
	AddressSpace getAddressSpace();
}
