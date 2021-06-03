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

import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;

/**
 * A dummy {@link MsSymbolApplier}, which, at a minimum, reads the symbol from the
 * {@link SymbolGroup}, allowing proper sequencing of other symbols within the
 * {@link SymbolGroup}.
 */
public class NoSymbolApplier extends MsSymbolApplier {

	private AbstractMsSymbol symbol;

	/**
	 * Constructor
	 * @param applicator the {@link PdbApplicator} for which we are working.
	 * @param iter the Iterator containing the symbol sequence being processed
	 */
	public NoSymbolApplier(PdbApplicator applicator, AbstractMsSymbolIterator iter) {
		super(applicator, iter);
		symbol = iter.next();
	}

	@Override
	void applyTo(MsSymbolApplier applyToApplier) {
		// Do nothing.
	}

	@Override
	void apply() {
		// Do nothing.
	}

}
