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
interface DeferrableFunctionSymbolApplier {

	/**
	 * Returns entry address of code/function that needs disassembled; this is the original,
	 * non-normalized address (e.g., odd if Thumb)
	 * @return the address
	 */
	Address getAddress();

	/**
	 * Deferred work for the MsSymbolApplier that can only be applied after all functions
	 *  have been created and disassembled.  Examples would be setting local variables and
	 *  parameters
	 */
	default void doDeferredProcessing() {
		// do nothing
	}

}
