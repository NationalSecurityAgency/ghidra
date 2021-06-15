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
// An exemplar script that allows the user to pass options to the Gnu Demangler.  One such
// option is the '-s arm' option which is hard coded into the script to show how it is done.
// See binutils' c++filt for more information on supported options.

//
//@category Examples.Demangler
import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.gnu.*;
import ghidra.program.model.symbol.Symbol;

public class DemangleElfWithOptionScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		GnuDemangler demangler = new GnuDemangler();
		if (!demangler.canDemangle(currentProgram)) {
			String executableFormat = currentProgram.getExecutableFormat();
			println(
				"Cannot use the elf demangling options for executable format: " + executableFormat);
			return;
		}

		Symbol symbol = null;
		if (currentAddress != null && (currentSelection == null || currentSelection.isEmpty())) {
			symbol = getSymbolAt(currentAddress);
		}
		if (symbol == null) {
			println("No symbol at the current address (selections are not supported)");
			return;
		}

		String mangled = symbol.getName();

		GnuDemanglerOptions options = new GnuDemanglerOptions(GnuDemanglerFormat.AUTO, false);
		options.setDoDisassembly(false);

		/*
			// for older formats use the deprecated demangler
			options = options.withDemanglerFormat(GnuDemanglerFormat.ARM, true);
		*/

		DemangledObject demangledObject = demangler.demangle(mangled, options);
		if (demangledObject == null) {
			println("Could not demangle: " + mangled);
			return;
		}

		println("Succesfully demangled " + mangled + " to " + demangledObject);
	}
}
