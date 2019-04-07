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
// Mips_Fix_T9_PositionIndependentCode is useful for a particular PIC (position independent code) trick used by some compilers.
// The T9 register is used as a base for all address calculations in each function.  The T9 register
// is set to the start of each function right before the function is called.  This is done by actually
// using the T9 register to call the other function.
//
// This could be modified if there is some other register being used.  However the compiler would need.
// to know this as it creates code, so it really is a calling convention.
//
// Usage:  This relies on functions having been created, so if a new function is created, you must
// re-run the script again.
//
// Important: Since it relies on functions being created, one should endeavor to find all function starts
// and actually create a function, then run this script.
//
// Future: This could be created as an automated analyzer, if one could detect that it should be run.
//
//@category Analysis.MIPS
//@keybinding 
//@menupath 
//@toolbar 

import java.math.BigInteger;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;

public class Mips_Fix_T9_PositionIndependentCode extends GhidraScript {

	@Override
	public void run() throws Exception {
		AddressSet doneSet = new AddressSet();

		while (processFunctions(doneSet)) {
			this.analyzeChanges(currentProgram);
		}

	}

	private boolean processFunctions(AddressSet doneSet) {
		Listing listing = currentProgram.getListing();

		Register t9 = currentProgram.getRegister("t9");
		if (t9 == null) {
			return false;
		}

		FunctionIterator fiter = listing.getFunctions(true);
		boolean didAnything = false;
		while (!monitor.isCancelled() && fiter.hasNext()) {
			Function func = fiter.next();

			Address funcEntry = func.getEntryPoint();

			if (doneSet.contains(funcEntry)) {
				continue;
			}
			doneSet.addRange(funcEntry, funcEntry);
			Instruction instr = listing.getInstructionAt(funcEntry);
			if (instr == null) {
				continue;
			}

			currentAddress = funcEntry;
			if (instr.getValue(t9, false) != null) {
				continue;
			}

			didAnything = true;

			println("" + func.getName());

			try {
				instr.setValue(t9, BigInteger.valueOf(funcEntry.getOffset()));
			}
			catch (ContextChangeException e) {
				println("  COULDN'T set context");
				e.printStackTrace();
			}

			GhidraState newState =
				new GhidraState(state.getTool(), state.getProject(), currentProgram,
					new ProgramLocation(currentProgram, currentAddress), null, null);

			try {
				this.runScript("PropagateConstantReferences.java", newState);
			}
			catch (Exception e) {
				println("Couldn't Run Propogate script");
				e.printStackTrace();
			}

			AutoAnalysisManager amgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
			amgr.codeDefined(func.getBody());
		}

		return didAnything;
	}

}
