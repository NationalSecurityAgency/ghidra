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

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.EndMsSymbol;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link EndMsSymbol} symbols.
 */
public class EndSymbolApplier extends MsSymbolApplier {

	/**
	 * Constructor
	 * @param applicator the {@link PdbApplicator} for which we are working.
	 * @param iter the Iterator containing the symbol sequence being processed
	 * @throws CancelledException upon user cancellation
	 */
	public EndSymbolApplier(PdbApplicator applicator, AbstractMsSymbolIterator iter) {
		super(applicator, iter);
		AbstractMsSymbol abstractSymbol = iter.next();
		if (!(abstractSymbol instanceof EndMsSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
	}

	@Override
	void apply() throws PdbException {
		pdbLogAndInfoMessage(this,
			String.format("Cannot apply %s directly to program (module:0X%04X, offset:0X%08X)",
				this.getClass().getSimpleName(), iter.getModuleNumber(), iter.getCurrentOffset()));
	}

	@Override
	void applyTo(MsSymbolApplier applyToApplier) {
		if (!(applyToApplier instanceof FunctionSymbolApplier)) {
			return;
		}
//		FunctionSymbolApplier functionSymbolApplier = (FunctionSymbolApplier) applyToApplier;
//		functionSymbolApplier.endBlock();
	}

	@Override
	void manageBlockNesting(MsSymbolApplier applierParam) {
		if (applierParam instanceof FunctionSymbolApplier) {
			FunctionSymbolApplier functionSymbolApplier = (FunctionSymbolApplier) applierParam;
			functionSymbolApplier.endBlock();
		}
		else if (applierParam instanceof SeparatedCodeSymbolApplier) {
			SeparatedCodeSymbolApplier separatedCodeSymbolApplier =
				(SeparatedCodeSymbolApplier) applierParam;
			separatedCodeSymbolApplier.endBlock();
		}
		else if (applierParam instanceof ManagedProcedureSymbolApplier) {
			ManagedProcedureSymbolApplier procedureSymbolApplier =
				(ManagedProcedureSymbolApplier) applierParam;
			procedureSymbolApplier.endBlock();
		}
	}
}
