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
package ghidra.app.util.pdb.pdbapplicator;

import ghidra.program.model.address.Address;

/**
 * Interface class for MsSymbolApplier that has deferrable function work.
 */
interface DisassembleableAddressSymbolApplier {

	/**
	 * Returns the address for disassembly.  Does not increment the iterator
	 * @return the address
	 */
	public Address getAddressForDisassembly();

}
