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
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractReferenceMsSymbol;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractReferenceMsSymbol} symbols.
 */
public class ReferenceSymbolApplier extends MsSymbolApplier {

	private AbstractReferenceMsSymbol symbol;

	/**
	 * Constructor
	 * @param applicator the {@link DefaultPdbApplicator} for which we are working.
	 * @param symbol the symbol for this applier
	 */
	public ReferenceSymbolApplier(DefaultPdbApplicator applicator,
			AbstractReferenceMsSymbol symbol) {
		super(applicator);
		this.symbol = symbol;
	}

	//TODO: since we stopped taking the references from publics/globals to module-based symbols
	//  and processing them that way and are now just processing directly from the
	//  modules, we need to determine if there is any use for these reference symbols.
	// We currently are not implementing the DirectSymbolApplier or the NestingSymbolApplier
	//  interfaces... so we are an applier just in form at this point.
	// => Re-evaluate!!!
//	@Override
//	public void apply(MsSymbolIterator iter) throws PdbException, CancelledException {
//		getValidatedSymbol(iter, true);
//		getValidatedSymbol(iter, true);
//		MsSymbolIterator refIter = getRefIterFromSymbol();
//		applicator.procSymNew(refIter);
//	}

	/**
	 * Checks check symbol from primary iterator for correct type and then retrieves the
	 * properly initialized reference iterator
	 * @return the initialized reference iterator
	 * @throws PdbException upon not enough data to parse
	 * @throws CancelledException upon user cancellation
	 */
	MsSymbolIterator getRefIterFromSymbol()
			throws CancelledException, PdbException {
		int refModuleNumber = symbol.getModuleIndex();
		MsSymbolIterator refIter =
			applicator.getPdb().getDebugInfo().getSymbolIterator(refModuleNumber);
		long refOffset = symbol.getOffsetActualSymbolInDollarDollarSymbols();
		refIter.initGetByOffset(refOffset);
		return refIter;
	}

	private AbstractReferenceMsSymbol getValidatedSymbol(MsSymbolIterator iter, boolean iterate) {
		AbstractMsSymbol abstractSymbol = iterate ? iter.next() : iter.peek();
		if (!(abstractSymbol instanceof AbstractReferenceMsSymbol refSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		return refSymbol;
	}

}
