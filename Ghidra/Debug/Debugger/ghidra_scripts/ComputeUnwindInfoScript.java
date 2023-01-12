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
//A script to analyze unwind information for the current function wrt. the current location
//as a program counter. The resulting information can be used to interpret how the function
//is using various elements on the stack when the program counter is at the cursor. This
//script is more for diagnostic and demonstration purposes, since the application of unwind
//information is already integrated into the Debugger.
//@author
//@category Stack
//@keybinding
//@menupath
//@toolbar

import java.util.Map.Entry;

import ghidra.app.plugin.core.debug.stack.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;

public class ComputeUnwindInfoScript extends GhidraScript {

	String addressToString(Address address) {
		Register[] registers = currentProgram.getLanguage().getRegisters(address);
		if (registers.length == 0) {
			return address.toString();
		}
		return registers[0].getBaseRegister().toString();
	}

	@Override
	protected void run() throws Exception {
		UnwindAnalysis ua = new UnwindAnalysis(currentProgram);
		UnwindInfo info = ua.computeUnwindInfo(currentAddress, monitor);

		if (info == null) {
			println("Could not unwind");
			return;
		}
		println("Stack depth at " + currentAddress + ": " + info.depth());
		println("Return address address: " + addressToString(info.ofReturn()));
		println("Saved registers:");
		for (Entry<Register, Address> entry : info.saved().entrySet()) {
			println("  " + entry);
		}
		println("Warnings:");
		for (StackUnwindWarning warning : info.warnings()) {
			println("  " + warning.getMessage());
		}
	}
}
