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
package ghidra.program.database.symbol;

import java.io.IOException;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.VariableStorage;

public interface VariableStorageManager {

	/**
	 * Get a variable address for the given storage specification.
	 * @param storage variable storage specification
	 * @param create if true a new variable address will be allocated if needed
	 * @return variable address which corresponds to the storage specification or null if not found
	 * and create is false.
	 * @throws IOException if an IO error occurs
	 */
	Address getVariableStorageAddress(VariableStorage storage, boolean create) throws IOException;
}
