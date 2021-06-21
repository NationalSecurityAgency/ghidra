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
package ghidra.program.model.data;

import ghidra.program.model.mem.MemBuffer;

/**
 * A DataType class that creates data types dynamically should implement this interface.
 * This prevents them being directly referred to by a data instance within the listing
 * or within a composite (e.g., added to a composite using the structure editor).
 * FactoryDataType's should never be parented (e.g., Pointer, Structure component, Typedef, etc.).
 */
public interface FactoryDataType extends BuiltInDataType {

	/**
	 * Returns the appropriate DataType which corresponds to the specified 
	 * memory location.
	 * @param buf memory location
	 * @return fabricated datatype based upon memory data
	 */
	DataType getDataType(MemBuffer buf);

	/**
	 * All implementations must return a length of -1.
	 * @return length of -1
	 */
	@Override
	default int getLength() {
		return -1;
	}

}
