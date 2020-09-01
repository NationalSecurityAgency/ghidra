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
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbLog;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractWithMsSymbol;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractWithMsSymbol} symbols.  This is not fully implemented
 *  because we do not know its usage or have examples, but we have implemented
 *  the block management portion.
 */
public class WithSymbolApplier extends AbstractMsSymbolApplier {

	private AbstractWithMsSymbol symbol;

	public WithSymbolApplier(PdbApplicator applicator, AbstractMsSymbolIterator iter) {
		super(applicator, iter);
		AbstractMsSymbol abstractSymbol = iter.next();
		if (!(abstractSymbol instanceof AbstractWithMsSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		symbol = (AbstractWithMsSymbol) abstractSymbol;
	}

	@Override
	public void apply() throws PdbException, CancelledException {
		// TODO: We do not know if this can be applied to a program or not.  We have no examples.
		String message = "Cannot apply " + this.getClass().getSimpleName() + " directly to program";
		Msg.info(this, message);
		PdbLog.message(message);
	}

	@Override
	public void applyTo(AbstractMsSymbolApplier applyToApplier) {
		// Do nothing
	}

	@Override
	public void manageBlockNesting(AbstractMsSymbolApplier applierParam) {
		if (applierParam instanceof FunctionSymbolApplier) {
			FunctionSymbolApplier functionSymbolApplier = (FunctionSymbolApplier) applierParam;
			Address address = applicator.reladdr(symbol);
			// TODO: not sure if getExpression() is correct, but there is no "name."
			functionSymbolApplier.beginBlock(address, symbol.getExpression(), symbol.getLength());
		}
	}
}
