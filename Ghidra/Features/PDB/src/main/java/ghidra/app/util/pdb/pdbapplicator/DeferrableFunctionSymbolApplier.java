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

import ghidra.app.util.bin.format.pdb2.pdbreader.MsSymbolIterator;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;

/**
 * Interface class for MsSymbolApplier that has deferrable function work.
 */
interface DeferrableFunctionSymbolApplier extends DirectSymbolApplier {

	/**
	 * Deferred work for the MsSymbolApplier that can only be applied after all functions
	 *  have been created and disassembled.  Examples would be setting local variables and
	 *  parameters
	 * @param iter the Iterator containing the symbol sequence being processed
	 * @throws PdbException if there was a problem processing the data
	 * @throws CancelledException upon user cancellation
	 */
	public void deferredApply(MsSymbolIterator iter) throws PdbException, CancelledException;

	/**
	 * Method to call to begin a block
	 * @param startAddress start address of block
	 * @param name name of the block
	 * @param length byte length of the block
	 */
	public void beginBlock(Address startAddress, String name, long length);

	/**
	 * Method to call to end a block
	 */
	public void endBlock();
}
