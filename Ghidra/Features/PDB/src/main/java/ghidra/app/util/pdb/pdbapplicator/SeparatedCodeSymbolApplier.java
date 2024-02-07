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
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.SeparatedCodeFromCompilerSupportMsSymbol;
import ghidra.program.model.address.Address;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link SeparatedCodeFromCompilerSupportMsSymbol} symbol.
 */
public class SeparatedCodeSymbolApplier extends AbstractBlockContextApplier
		implements BlockNestingSymbolApplier, NestableSymbolApplier {

	private SeparatedCodeFromCompilerSupportMsSymbol symbol;

	/**
	 * Constructor
	 * @param applicator the {@link DefaultPdbApplicator} for which we are working.
	 * @param symbol the symbol for this applier
	 */
	public SeparatedCodeSymbolApplier(DefaultPdbApplicator applicator,
			SeparatedCodeFromCompilerSupportMsSymbol symbol) {
		super(applicator);
		this.symbol = symbol;
	}

	@Override
	public void apply(MsSymbolIterator iter) throws PdbException, CancelledException {
		getValidatedSymbol(iter, true);
		Address address = applicator.getAddress(symbol);

		// Regardless of ability to apply this symbol, we need to progress through symbols to the
		//  matching "end" symbol before we return
		if (!processEndSymbol(symbol.getEndPointer(), iter)) {
			applicator.appendLogMsg("PDB: Failed to process function at address " + address);
			return;
		}

		if (applicator.isInvalidAddress(address, craftBlockComment(address))) {
			return;
		}

		// Although this is code, we do not create a function here or perform disassembly.
		//  The Decompiler should be able to track flow to this location from the parent.
		//  Just applying a plate comment here to identify this block in the code browser.
		//  Note, however, there are some flags that could be useful, such as "returns to parent."
		applyPlateComment(address);
//		Function function = applicator.getExistingOrCreateOneByteFunction(address);
//		if (function == null) {
//			return;
//		}
//
//		// Collecting all addresses from all functions to do one large bulk disassembly of the
//		//  complete AddressSet of function addresses.  We could consider removing this logic
//		//  of collecting them all for bulk disassembly and do individual disassembly at the
//		//  same deferred point in time.
//		applicator.scheduleDisassembly(address);
	}

	@Override
	public void deferredApply(MsSymbolIterator iter)
			throws PdbException, CancelledException {
		// Pealing the symbol off again, as the iterator is coming in fresh, and we need the symbol
		getValidatedSymbol(iter, true);

		Address address = applicator.getAddress(symbol);

		long start = getStartOffset();
		long end = getEndOffset();
		Address blockAddress = address.add(start);
		long length = end - start;

		// Not sure if following procedure from parent class can be used or if should be
		//  specialized here
		deferredProcessing(iter, craftBlockComment(blockAddress), address, blockAddress, length);
	}

	private String craftBlockComment(Address address) {
		return String.format("CompilerSeparatedCode%s", address);
	}

	private void applyPlateComment(Address address) {
		Address parentAddress =
			applicator.getAddress(symbol.getSegmentParent(), symbol.getOffsetParent());
		String comment = String.format(
			"PDB: Separated code (from the compiler): %s - %s for parent address: %s",
			address.toString(),
			address.add(symbol.getBlockLength() - 1).toString(), parentAddress.toString());
		applicator.addToPlateUnique(address, comment);
	}

	@Override
	public void applyTo(NestingSymbolApplier applyToApplier, MsSymbolIterator iter)
			throws PdbException, CancelledException {
		getValidatedSymbol(iter, true);
		if (applyToApplier instanceof AbstractBlockContextApplier applier) {
			Address address = applicator.getAddress(symbol);
			applier.beginBlock(address, null, 0);
		}
	}

	@Override
	long getStartOffset() {
		return symbol.getParentPointer(); // TODO: needs investigation as to what field to use!!!!!
	}

	@Override
	long getEndOffset() {
		return symbol.getEndPointer(); // TODO: needs investigation as to what field to use!!!!!
	}

	boolean returnsToParent() {
		return symbol.returnsToParent();
	}

	private SeparatedCodeFromCompilerSupportMsSymbol getValidatedSymbol(MsSymbolIterator iter,
			boolean iterate) {
		AbstractMsSymbol abstractSymbol = iterate ? iter.next() : iter.peek();
		if (!(abstractSymbol instanceof SeparatedCodeFromCompilerSupportMsSymbol sepCodeSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		return sepCodeSymbol;
	}

}
