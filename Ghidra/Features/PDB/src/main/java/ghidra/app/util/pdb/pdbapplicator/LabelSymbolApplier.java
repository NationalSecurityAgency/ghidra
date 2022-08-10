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

import java.util.regex.Matcher;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractLabelMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractLabelMsSymbol} symbols.
 */
public class LabelSymbolApplier extends MsSymbolApplier {

	private AbstractLabelMsSymbol symbol;

	/**
	 * Constructor
	 * @param applicator the {@link DefaultPdbApplicator} for which we are working.
	 * @param iter the Iterator containing the symbol sequence being processed
	 */
	public LabelSymbolApplier(DefaultPdbApplicator applicator, AbstractMsSymbolIterator iter) {
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
		String label = getLabel();
		if (label == null) {
			return;
		}

		Address symbolAddress = applicator.getAddress(symbol);
		if (applicator.isInvalidAddress(symbolAddress, label)) {
			return;
		}
		applicator.createSymbol(symbolAddress, label, false);
	}

	@Override
	void applyTo(MsSymbolApplier applyToApplier) {
		String label = getLabel();
		if (label == null) {
			return;
		}

		Address symbolAddress = applicator.getAddress(symbol);
		if (applicator.isInvalidAddress(symbolAddress, label)) {
			return;
		}

		if (applyToApplier instanceof FunctionSymbolApplier functionSymbolApplier) {
			Function f = functionSymbolApplier.getFunction();
			if (f != null && !f.getName().equals(label)) {
				label = NamespaceUtils.getNamespaceQualifiedName(f, label, true);
			}
		}

		// No longer doing this, but instead letting namespace come from GPROC sequence... that way,
		// labels will pertain to functions even if landing inside other function address range.
		// Keeping code here (commented out), replaced by above code, until we get other issues
		// figured out.
//		FunctionManager functionManager = applicator.getProgram().getFunctionManager();
//		// TODO: What do we do with labels such as this?... "__catch$?test_eh1@@YAHXZ$7"
//		if (!label.contains(Namespace.DELIMITER)) {
//			Function f = functionManager.getFunctionContaining(symbolAddress);
//			if (f != null && !f.getName().equals(label)) {
//				label = NamespaceUtils.getNamespaceQualifiedName(f, label, true);
//			}
//		}

		// TODO: Before we turn on label applications.... we probably need to change order on
		// how function symbols are applied.  Perhaps we need to apply all GPROC symbols before
		// we apply their internals (frames, local vars, labels, blocks) because some labels (here)
		// are getting applied and becoming primary (because some have addresses that are located
		// outside of the the address range of their GPROC, and will prevent another GPROC at the
		// same address as the label from becoming primary (e.g., $LN7 of cn3 at a750).
		applicator.createSymbol(symbolAddress, label, false);
	}

	/**
	 * Returns label to apply or null if label excluded
	 * @return label to process or null
	 */
	private String getLabel() {
		if (!applicator.getPdbApplicatorOptions().applyInstructionLabels()) {
			return null;
		}
		// Place compiler generated symbols (e.g., $LN9) within containing function when possible
		String label = symbol.getName();
		Matcher m =
			applicator.getPdbApplicatorOptions().excludeInstructionLabelsPattern().matcher(label);
		if (m.find()) {
			return null;
		}
		return label;
	}
}
