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
//Output MDMang parse information to the console.
//
//@category Demangler

import docking.*;
import ghidra.app.context.ProgramSymbolActionContext;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.*;
import ghidra.util.Msg;
import mdemangler.MDException;
import mdemangler.MDMangParseInfo;

public class DeveloperDumpMDMangParseInfoScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
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

		if (name == null || name.length() == 0) {
			Msg.info(this, "Invalid name.\n");
			return;
		}

		StringBuilder builder = new StringBuilder();
		builder.append("\nName: " + name + "\n");
		MDMangParseInfo demangler = new MDMangParseInfo();
		try {
			demangler.demangle(name, false);
			String parseInfo = demangler.getParseInfoIncremental();
			builder.append(parseInfo);
			builder.append("Num remaining chars:" + demangler.getNumCharsRemaining() + "\n");
		}
		catch (MDException e) {
			builder.append("Demangler failure: " + e.getMessage() + "\n");
		}
		Msg.info(this, builder);
	}

}
