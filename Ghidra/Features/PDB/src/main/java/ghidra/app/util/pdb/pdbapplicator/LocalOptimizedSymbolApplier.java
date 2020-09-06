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
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractLocalSymbolInOptimizedCodeMsSymbol} symbols.
 */
public class LocalOptimizedSymbolApplier extends MsSymbolApplier {

	private AbstractLocalSymbolInOptimizedCodeMsSymbol symbol;

	/**
	 * Constructor
	 * @param applicator the {@link PdbApplicator} for which we are working.
	 * @param iter the Iterator containing the symbol sequence being processed
	 */
	public LocalOptimizedSymbolApplier(PdbApplicator applicator, AbstractMsSymbolIterator iter) {
		super(applicator, iter);
		AbstractMsSymbol abstractSymbol = iter.next();
		if (!(abstractSymbol instanceof AbstractLocalSymbolInOptimizedCodeMsSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		symbol = (AbstractLocalSymbolInOptimizedCodeMsSymbol) abstractSymbol;
	}

	@Override
	void apply() throws PdbException, CancelledException {
		pdbLogAndInfoMessage(this,
			"Cannot apply " + this.getClass().getSimpleName() + " directly to program");
	}

	@Override
	void applyTo(MsSymbolApplier applyToApplier) throws PdbException, CancelledException {
		if (!applicator.getPdbApplicatorOptions().applyFunctionVariables()) {
			return;
		}
		if (applyToApplier instanceof FunctionSymbolApplier) {
			FunctionSymbolApplier functionSymbolApplier = (FunctionSymbolApplier) applyToApplier;
			doWork(functionSymbolApplier);
		}
	}

	private void doWork(FunctionSymbolApplier functionSymbolApplier)
			throws CancelledException, PdbException {
		// TODO: Not doing anything with the information yet.
		symbol.getLocalVariableFlags();
		symbol.getName();
		symbol.getTypeRecordNumber();
		while (iter.hasNext() &&
			(iter.peek() instanceof AbstractDefinedSingleAddressRangeMsSymbol)) {
			applicator.checkCanceled();
			DefinedSingleAddressRangeSymbolApplier rangeApplier =
				new DefinedSingleAddressRangeSymbolApplier(applicator, iter);
			rangeApplier.applyTo(this);
		}
	}

}
