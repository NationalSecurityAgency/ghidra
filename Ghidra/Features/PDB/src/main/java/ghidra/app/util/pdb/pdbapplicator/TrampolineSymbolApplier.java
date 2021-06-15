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

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.TrampolineMsSymbol;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link TrampolineMsSymbol} symbols.
 */
public class TrampolineSymbolApplier extends MsSymbolApplier {

	private TrampolineMsSymbol symbol;

	/**
	 * Constructor
	 * @param applicator the {@link PdbApplicator} for which we are working.
	 * @param iter the Iterator containing the symbol sequence being processed
	 */
	public TrampolineSymbolApplier(PdbApplicator applicator, AbstractMsSymbolIterator iter) {
		super(applicator, iter);
		AbstractMsSymbol abstractSymbol = iter.next();
		if (!(abstractSymbol instanceof TrampolineMsSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		symbol = (TrampolineMsSymbol) abstractSymbol;
	}

	@Override
	void applyTo(MsSymbolApplier applyToApplier) {
		// Do nothing.
	}

	@Override
	void apply() throws CancelledException, PdbException {
		// We know the size of this trampoline, so use it to restrict the disassembly.
		Address symbolAddress = applicator.getAddress(symbol);
		Address targetAddress =
			applicator.getAddress(symbol.getSegmentTarget(), symbol.getOffsetTarget());

		Function target = null;
		Function thunk = null;
		if (!applicator.isInvalidAddress(targetAddress, "thunk target")) {
			target = createNewFunction(targetAddress, 1);
		}
		if (!applicator.isInvalidAddress(symbolAddress, "thunk symbol")) {
			thunk = createNewFunction(symbolAddress, symbol.getSizeOfThunk());
		}
		if (target != null && thunk != null) {
			thunk.setThunkedFunction(target);
		}
//		int thunkModule = findModuleNumberBySectionOffsetContribution(symbol.getSectionThunk(),
//			symbol.getOffsetThunk());
//		int targetModule = findModuleNumberBySectionOffsetContribution(symbol.getSectionTarget(),
//			symbol.getOffsetTarget());

	}

	// TODO? If we wanted to be able to apply this symbol to a different address, we should 
	//  review code in FunctionSymbolApplier.  Note, however, that there are two addresses
	//  that need to be dealt with here, and each could have a different address with a different
	//  delta from the specified address.

	private Function createNewFunction(Address startAddress, long size) {

		AddressSet addressSet = new AddressSet(startAddress, startAddress.add(size));

		if (applicator.getProgram().getListing().getInstructionAt(startAddress) == null) {
			DisassembleCommand cmd = new DisassembleCommand(addressSet, null, true); // TODO: false?
			cmd.applyTo(applicator.getProgram(), applicator.getCancelOnlyWrappingMonitor());
		}

		// Only create function if it does not already exist.
		Function function = applicator.getProgram().getListing().getFunctionAt(startAddress);
		if (function != null) {
			return function;
		}
		CreateFunctionCmd funCmd = new CreateFunctionCmd(startAddress);
		if (!funCmd.applyTo(applicator.getProgram(), applicator.getCancelOnlyWrappingMonitor())) {
			applicator.appendLogMsg("Failed to apply function at address " +
				startAddress.toString() + "; attempting to use possible existing function");
		}
		return funCmd.getFunction();
	}

}
