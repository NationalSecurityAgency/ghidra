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
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.ProcedureIdEndMsSymbol;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link ProcedureIdEndMsSymbol} symbols.
 */
public class ProcedureIdEndSymbolApplier extends MsSymbolApplier
		implements BlockNestingSymbolApplier, NestableSymbolApplier {

	private ProcedureIdEndMsSymbol symbol;

	/**
	 * Constructor
	 * @param applicator the {@link DefaultPdbApplicator} for which we are working.
	 * @param symbol the symbol for this applier
	 */
	public ProcedureIdEndSymbolApplier(DefaultPdbApplicator applicator,
			ProcedureIdEndMsSymbol symbol) {
		super(applicator);
		this.symbol = symbol;
	}

	@Override
	public void applyTo(NestingSymbolApplier applyToApplier, MsSymbolIterator iter)
			throws PdbException, CancelledException {
		getValidatedSymbol(iter, true);
		if (applyToApplier instanceof AbstractBlockContextApplier applier) {
			applier.endBlock();
		}
	}

	private ProcedureIdEndMsSymbol getValidatedSymbol(MsSymbolIterator iter, boolean iterate) {
		AbstractMsSymbol abstractSymbol = iterate ? iter.next() : iter.peek();
		if (!(abstractSymbol instanceof ProcedureIdEndMsSymbol endSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		return endSymbol;
	}

}
