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
//Attempts to demangle the symbol at the current location using Ghidra's DemanglerCmd and replace 
//the default symbol and function signature (if applicable) with the demangled symbol
//Works for both Microsoft and Gnu mangled symbols
//@category Symbol

import ghidra.app.cmd.label.DemanglerCmd;
import ghidra.app.context.ProgramSymbolActionContext;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.*;
import docking.*;

public class DemangleSymbolScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		DockingWindowManager windowManager = DockingWindowManager.getActiveInstance();
		ComponentProvider provider = windowManager.getActiveComponentProvider();
		ActionContext actionContext = provider.getActionContext(null);
		if (actionContext instanceof ProgramSymbolActionContext) {
			ProgramSymbolActionContext symbolContext = (ProgramSymbolActionContext) actionContext;
			for (Symbol s : symbolContext.getSymbols()) {
				demangle(s.getAddress(), s.getName());
			}
		}
		else if (currentLocation instanceof FunctionSignatureFieldLocation) {
			Function function = getFunctionAt(currentAddress);
			if (function != null) {
				demangle(currentAddress, function.getName());
			}
		}
		else if (currentLocation instanceof LabelFieldLocation) {
			LabelFieldLocation lfl = (LabelFieldLocation) currentLocation;
			demangle(currentAddress, lfl.getName());
		}
		else if (currentLocation instanceof OperandFieldLocation) {
			Data data = getDataAt(currentAddress);
			if (data == null) {
				return;
			}

			Object value = data.getValue();
			if (!(value instanceof Address)) {
				return;
			}

			Address symbolAddr = (Address) value;
			Symbol sym = getSymbolAt(symbolAddr);
			if (sym == null) {
				popup("Symbol not found at the address " + symbolAddr +
					" referenced by the selected pointer");
				return;
			}
			demangle(symbolAddr, sym.getName());
		}
		else {
			Symbol sym = getSymbolAt(currentAddress);
			if (sym != null) {
				demangle(currentAddress, sym.getName());
			}
			else {
				println("Nothing to demangle at " + currentAddress);
			}
		}
	}

	private void demangle(Address address, String name) {
		if (name.startsWith("s_") || name.startsWith("u_") || name.startsWith("AddrTable")) {
			println("Not a mangled name: " + name);
			return;
		}

		if (name.indexOf("::case_0x") > 0) {
			int pos = name.indexOf("::case_0x");
			name = name.substring(0, pos);
		}
		else if (name.indexOf("::switchTable") > 0) {
			int pos = name.indexOf("::switchTable");
			name = name.substring(0, pos);
		}

		DemanglerCmd cmd = new DemanglerCmd(address, name);
		boolean success = cmd.applyTo(currentProgram, monitor);
		if (success) {
			println("Successfully demangled!\n" + name + '\n' + cmd.getResult());
		}
		else {
			println(cmd.getStatusMsg());
		}
	}
}
