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
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractManagedSymbolWithSlotIndexFieldMsSymbol} symbols.
 */
public class UsingNamespaceSymbolApplier extends MsSymbolApplier
		implements NestableSymbolApplier {

	private AbstractUsingNamespaceMsSymbol symbol;

	/**
	 * Constructor
	 * @param applicator the {@link DefaultPdbApplicator} for which we are working.
	 * @param symbol the symbol for this applier
	 */
	public UsingNamespaceSymbolApplier(DefaultPdbApplicator applicator,
			AbstractUsingNamespaceMsSymbol symbol) {
		super(applicator);
		this.symbol = symbol;
	}

	//==============================================================================================
	//TODO: wondering if this can be seen in direct (non-nested use), like file-static.  Need
	//  to study data.  If so, make sure has DirectSymbolApplier interface above
//	@Override
//	void apply(MsSymbolIterator iter) throws PdbException, CancelledException {
//		// Pealing the symbol off again, as the iterator is coming in fresh, and we need the symbol
//		getValidatedSymbol(iter, true);
//	}

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

	private AbstractUsingNamespaceMsSymbol getValidatedSymbol(
			MsSymbolIterator iter, boolean iterate) {
		AbstractMsSymbol abstractSymbol = iterate ? iter.next() : iter.peek();
		if (!(abstractSymbol instanceof AbstractUsingNamespaceMsSymbol usingNamespaceSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		return usingNamespaceSymbol;
	}

}
