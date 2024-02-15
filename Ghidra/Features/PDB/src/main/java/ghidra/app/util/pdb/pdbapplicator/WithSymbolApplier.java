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
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractWithMsSymbol;
import ghidra.program.model.address.Address;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractWithMsSymbol} symbols.  This is not fully implemented
 * because we do not know its usage or have examples, but we have implemented
 * the block management portion.
 */
public class WithSymbolApplier extends MsSymbolApplier
		implements BlockNestingSymbolApplier, NestableSymbolApplier { // Not sure about nestable

	private AbstractWithMsSymbol symbol;

	/**
	 * Constructor
	 * @param applicator the {@link DefaultPdbApplicator} for which we are working.
	 * @param symbol the symbol for this applier
	 */
	public WithSymbolApplier(DefaultPdbApplicator applicator, AbstractWithMsSymbol symbol) {
		super(applicator);
		this.symbol = symbol;
	}

	// TODO: evaluate whether this can be applied directly to a program
//	@Override
//	public void apply(MsSymbolIterator iter) throws PdbException, CancelledException {
//		getValidatedSymbol(iter, true);
//		// TODO: We do not know if this can be applied to a program or not.  We have no examples.
//		pdbLogAndInfoMessage(this,
//			"Cannot apply " + this.getClass().getSimpleName() + " directly to program");
//	}

	@Override
	public void applyTo(NestingSymbolApplier applyToApplier, MsSymbolIterator iter)
			throws PdbException, CancelledException {
		getValidatedSymbol(iter, true);
		if (applyToApplier instanceof AbstractBlockContextApplier applier) {
			Address address = applicator.getAddress(symbol);
			applier.beginBlock(address, symbol.getExpression(), symbol.getLength());
		}
	}

	private AbstractWithMsSymbol getValidatedSymbol(MsSymbolIterator iter, boolean iterate) {
		AbstractMsSymbol abstractSymbol = iterate ? iter.next() : iter.peek();
		if (!(abstractSymbol instanceof AbstractWithMsSymbol withSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		return withSymbol;
	}

}
