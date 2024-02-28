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

//Outputs the natively demangled Swift symbol found at the current address in expanded tree form.
//Mostly useful for debugging.
//@category Demangler
import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.swift.*;
import ghidra.app.util.demangler.swift.SwiftNativeDemangler.SwiftNativeDemangledOutput;
import ghidra.program.model.symbol.*;

public class SwiftDemanglerScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		SwiftDemangler demangler = new SwiftDemangler(currentProgram);
		SwiftDemanglerOptions options = new SwiftDemanglerOptions();
		if (!demangler.canDemangle(currentProgram)) {
			println("Not a Swift program");
			return;
		}
		println("-------------------------------------------------");

		String mangled = null;
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		for (Symbol symbol : symbolTable.getSymbols(currentAddress)) {
			if (demangler.isSwiftMangledSymbol(symbol.getName())) {
				mangled = symbol.getName();
				break;
			}
			for (LabelHistory history : symbolTable.getLabelHistory(currentAddress)) {
				if (demangler.isSwiftMangledSymbol(history.getLabelString())) {
					mangled = history.getLabelString();
					break;
				}
			}
		}
		if (mangled == null) {
			println("No mangled Swift symbols found at " + currentAddress);
			return;
		}
		
		SwiftNativeDemangler nativeDemangler = new SwiftNativeDemangler(options.getSwiftDir());
		SwiftNativeDemangledOutput demangledOutput = nativeDemangler.demangle(mangled);
		println(demangledOutput.toString());
		
		DemangledObject demangledObject = demangler.demangle(mangled);
		if (demangledObject != null) {
			println(demangledObject.getClass().getSimpleName() + " " + mangled + " --> " +
				demangledObject);
		}
		else {
			println("Failed to demangle: " + mangled);
		}
	}
}
