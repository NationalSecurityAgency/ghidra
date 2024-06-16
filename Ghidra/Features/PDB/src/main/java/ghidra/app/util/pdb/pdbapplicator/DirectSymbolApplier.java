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
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.util.exception.CancelledException;

/**
 * Interface class for MsSymbolApplier that has deferrable function work.
 */
interface DirectSymbolApplier {

	/**
	 * Apply the next and any desired subsequent {@link AbstractMsSymbol AbstractMsSymbols} from
	 * the {@link SymbolGroup} to a program.
	 * @param iter the Iterator containing the symbol sequence being processed
	 * @throws PdbException if there was a problem processing the data.
	 * @throws CancelledException upon user cancellation
	 */
	public void apply(MsSymbolIterator iter) throws PdbException, CancelledException;

}
