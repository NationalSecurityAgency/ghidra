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
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractManagedSymbolWithSlotIndexFieldMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractManagedSymbolWithSlotIndexFieldMsSymbol} symbols.
 */
public class ManagedSymbolWithSlotSymbolApplier extends MsSymbolApplier
		implements NestableSymbolApplier {

	private AbstractManagedSymbolWithSlotIndexFieldMsSymbol symbol;

	/**
	 * Constructor
	 * @param applicator the {@link DefaultPdbApplicator} for which we are working.
	 * @param symbol the symbol for this applier
	 */
	public ManagedSymbolWithSlotSymbolApplier(DefaultPdbApplicator applicator,
			AbstractManagedSymbolWithSlotIndexFieldMsSymbol symbol) {
		super(applicator);
		this.symbol = symbol;
	}

	//==============================================================================================
	@Override
	public void applyTo(NestingSymbolApplier applyToApplier, MsSymbolIterator iter)
			throws PdbException, CancelledException {
		// Pealing the symbol off again, as the iterator is coming in fresh, and we need the symbol
		getValidatedSymbol(iter, true);
		if (applyToApplier instanceof AbstractBlockContextApplier applier) {
			// TODO: figure out what needs to be done.
		}
	}

	private AbstractManagedSymbolWithSlotIndexFieldMsSymbol getValidatedSymbol(
			MsSymbolIterator iter, boolean iterate) {
		AbstractMsSymbol abstractSymbol = iterate ? iter.next() : iter.peek();
		if (!(abstractSymbol instanceof AbstractManagedSymbolWithSlotIndexFieldMsSymbol slotSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		return slotSymbol;
	}

}
