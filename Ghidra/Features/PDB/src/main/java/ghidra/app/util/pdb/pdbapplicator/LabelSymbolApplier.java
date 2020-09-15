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

import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractLabelMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractLabelMsSymbol} symbols.
 */
public class LabelSymbolApplier extends MsSymbolApplier {

	private AbstractLabelMsSymbol symbol;

	/**
	 * Constructor
	 * @param applicator the {@link PdbApplicator} for which we are working.
	 * @param iter the Iterator containing the symbol sequence being processed
	 * @throws CancelledException upon user cancellation
	 */
	public LabelSymbolApplier(PdbApplicator applicator, AbstractMsSymbolIterator iter) {
		super(applicator, iter);
		AbstractMsSymbol abstractSymbol = iter.next();
		if (!(abstractSymbol instanceof AbstractLabelMsSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		symbol = (AbstractLabelMsSymbol) abstractSymbol;
	}

	@Override
	void apply() throws PdbException, CancelledException {
		if (!applicator.getPdbApplicatorOptions().applyInstructionLabels()) {
			return;
		}
		// Place compiler generated symbols (e.g., $LN9) within containing function when possible
		String name = symbol.getName();
		Address symbolAddress = applicator.getAddress(symbol);
		if (applicator.isInvalidAddress(symbolAddress, name)) {
			return;
		}
		FunctionManager functionManager = applicator.getProgram().getFunctionManager();
		// TODO: What do we do with labels such as this?... "__catch$?test_eh1@@YAHXZ$7"
		if (name.startsWith("$") && !name.contains(Namespace.DELIMITER)) {
			Function f = functionManager.getFunctionContaining(symbolAddress);
			if (f != null && !f.getName().equals(name)) {
				name = NamespaceUtils.getNamespaceQualifiedName(f, name, true);
			}
		}
		applicator.createSymbol(symbolAddress, symbol.getName(), false);
	}

	@Override
	void applyTo(MsSymbolApplier applyToApplier) {
		// Do nothing
	}
}
