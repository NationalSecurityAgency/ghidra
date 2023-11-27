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
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.TrampolineMsSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link TrampolineMsSymbol} symbols.
 */
public class TrampolineSymbolApplier extends MsSymbolApplier
		implements DeferrableFunctionSymbolApplier {

	private TrampolineMsSymbol symbol;
	private Address address;

	/**
	 * Constructor
	 * @param applicator the {@link DefaultPdbApplicator} for which we are working.
	 * @param iter the Iterator containing the symbol sequence being processed
	 */
	public TrampolineSymbolApplier(DefaultPdbApplicator applicator, MsSymbolIterator iter) {
		super(applicator, iter);
		AbstractMsSymbol abstractSymbol = iter.next();
		if (!(abstractSymbol instanceof TrampolineMsSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		symbol = (TrampolineMsSymbol) abstractSymbol;
		address = applicator.getAddress(symbol);
	}

	@Override
	void applyTo(MsSymbolApplier applyToApplier) {
		// Do nothing.
	}

	@Override
	void apply() throws CancelledException, PdbException {
		// We know the size of this trampoline, so use it to restrict the disassembly.
		Address targetAddress =
			applicator.getAddress(symbol.getSegmentTarget(), symbol.getOffsetTarget());

		Function target = null;
		Function thunk = null;
		if (!applicator.isInvalidAddress(targetAddress, "thunk target")) {
			target = applicator.getExistingOrCreateOneByteFunction(targetAddress);
		}
		if (!applicator.isInvalidAddress(address, "thunk symbol")) {
			thunk = applicator.getExistingOrCreateOneByteFunction(address);
		}
		if (target != null && thunk != null) {
			thunk.setThunkedFunction(target);
		}
		applicator.scheduleDeferredFunctionWork(this);

//		int thunkModule = findModuleNumberBySectionOffsetContribution(symbol.getSectionThunk(),
//			symbol.getOffsetThunk());
//		int targetModule = findModuleNumberBySectionOffsetContribution(symbol.getSectionTarget(),
//			symbol.getOffsetTarget());

	}

	@Override
	public Address getAddress() {
		return address;
	}

	// TODO? If we wanted to be able to apply this symbol to a different address, we should
	//  review code in FunctionSymbolApplier.  Note, however, that there are two addresses
	//  that need to be dealt with here, and each could have a different address with a different
	//  delta from the specified address.

}
