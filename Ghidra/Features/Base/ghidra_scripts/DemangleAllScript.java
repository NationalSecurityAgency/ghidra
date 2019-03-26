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
//Attempts to demangle all mangled symbols in the current program using Ghidra's DemanglerCmd and 
//replace the default symbol and function signature (if applicable) with the demangled symbol
//Works for both Microsoft and Gnu mangled symbols
//@category Symbol

import ghidra.app.cmd.label.DemanglerCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;

public class DemangleAllScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		SymbolTable st = currentProgram.getSymbolTable();
		SymbolIterator it = st.getDefinedSymbols();

		while (it.hasNext() && !monitor.isCancelled()) {
			Symbol s = it.next();
			if (s.getSource() == SourceType.DEFAULT) {
				continue;
			}
			Address addr = s.getAddress();
			String name = s.getName();

			if (name.startsWith("s_") || name.startsWith("u_") || name.startsWith("AddrTable")) {
				continue;
			}

			if (name.indexOf("::case_0x") > 0) {
				int pos = name.indexOf("::case_0x");
				name = name.substring(0, pos);
			}
			else if (name.indexOf("::switchTable") > 0) {
				int pos = name.indexOf("::switchTable");
				name = name.substring(0, pos);
			}

			DemanglerCmd cmd = new DemanglerCmd(addr, name);
			if (!cmd.applyTo(currentProgram, monitor)) {
				println("Unable to demangle: " + s.getName());
			}
		}
	}
}
