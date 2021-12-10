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
package ghidra.program.model.symbol;

import ghidra.program.model.address.Address;

/**
 * <code>OffsetReference</code> is a memory reference whose "to" address is
 * computed from a base address plus an offset.
 */
public interface OffsetReference extends Reference {

	/**
	 * Returns the offset.
	 * @return the offset
	 */
	public long getOffset();

	/**
	 * Returns the base address.
	 * @return the address
	 */
	public Address getBaseAddress();

}
