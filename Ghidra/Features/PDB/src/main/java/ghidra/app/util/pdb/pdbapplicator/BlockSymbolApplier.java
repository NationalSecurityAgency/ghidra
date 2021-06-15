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
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractBlockMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;
import ghidra.program.model.address.Address;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractBlockMsSymbol} symbols.
 */
public class BlockSymbolApplier extends MsSymbolApplier {

	private AbstractBlockMsSymbol symbol;

	/**
	 * Constructor
	 * @param applicator the {@link PdbApplicator} for which we are working.
	 * @param iter the Iterator containing the symbol sequence being processed
	 */
	public BlockSymbolApplier(PdbApplicator applicator, AbstractMsSymbolIterator iter) {
		super(applicator, iter);
		AbstractMsSymbol abstractSymbol = iter.next();
		if (!(abstractSymbol instanceof AbstractBlockMsSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		symbol = (AbstractBlockMsSymbol) abstractSymbol;
	}

	@Override
	void apply() throws PdbException, CancelledException {
		pdbLogAndInfoMessage(this,
			"Cannot apply " + this.getClass().getSimpleName() + " directly to program");
	}

	@Override
	void applyTo(MsSymbolApplier applyToApplier) {
		// Do nothing
	}

	@Override
	void manageBlockNesting(MsSymbolApplier applierParam) {
		Address address = applicator.getAddress(symbol);
		if (applierParam instanceof FunctionSymbolApplier) {
			FunctionSymbolApplier functionSymbolApplier = (FunctionSymbolApplier) applierParam;
			functionSymbolApplier.beginBlock(address, symbol.getName(), symbol.getLength());
		}
		else if (applierParam instanceof SeparatedCodeSymbolApplier) {
			SeparatedCodeSymbolApplier separatedCodeSymbolApplier =
				(SeparatedCodeSymbolApplier) applierParam;
			separatedCodeSymbolApplier.beginBlock(address);
		}
		else if (applierParam instanceof ManagedProcedureSymbolApplier) {
			ManagedProcedureSymbolApplier procedureSymbolApplier =
				(ManagedProcedureSymbolApplier) applierParam;
			procedureSymbolApplier.beginBlock(address, symbol.getName(), symbol.getLength());
		}
	}
}
