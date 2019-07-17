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
import java.io.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.gnu.GnuDemanglerParser;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.framework.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.symbol.Symbol;

public class DemangleElfWithOptionScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		String executableFormat = currentProgram.getExecutableFormat();
		if (!canDemangle(executableFormat)) {
			println("Cannot use the elf demangling options for executable format: " +
				executableFormat);
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

		Process process = createProcess(executableFormat);

		InputStream in = process.getInputStream();
		OutputStream out = process.getOutputStream();

		BufferedReader input = new BufferedReader(new InputStreamReader(in));
		PrintWriter output = new PrintWriter(out);

		output.println(mangled);
		output.flush();
		String demangled = input.readLine();
		println("demangled: " + demangled);

		GnuDemanglerParser parser = new GnuDemanglerParser(null);
		DemangledObject demangledObject = parser.parse(mangled, demangled);
		if (demangledObject == null) {
			println("Could not demangle: " + mangled);
			return;
		}

		DemanglerOptions options = new DemanglerOptions();
		options.setDoDisassembly(false);
		options.setApplySignature(true);
		options.setDemangleOnlyKnownPatterns(true);

		if (!demangledObject.applyTo(currentProgram, currentAddress, options, monitor)) {
			println("Failed to apply demangled data for " + mangled);
		}
		println("Succesfully demangled " + mangled + " to " + demangled);
	}

	private boolean canDemangle(String executableFormat) {

		//check if language is GCC - this is not altogether correct !
		// Objective-C and other non-GCC based symbols may be handled improperly

		if (isELF(executableFormat) || isMacho(executableFormat)) {
			return true;
		}

		CompilerSpec compilerSpec = currentProgram.getCompilerSpec();
		if (compilerSpec.getCompilerSpecID().getIdAsString().toLowerCase().indexOf("windows") == -1) {
			return true;
		}
		return false;
	}

	private boolean isELF(String executableFormat) {
		return executableFormat != null && executableFormat.indexOf(ElfLoader.ELF_NAME) != -1;
	}

	private boolean isMacho(String executableFormat) {
		return executableFormat != null && executableFormat.indexOf(MachoLoader.MACH_O_NAME) != -1;
	}

	private Process createProcess(String executableName) throws Exception {

		OperatingSystem OS = Platform.CURRENT_PLATFORM.getOperatingSystem();
		String demanglerExe =
			(OS == OperatingSystem.WINDOWS) ? "demangler_gnu.exe" : "demangler_gnu";
		File commandPath = Application.getOSFile("GnuDemangler", demanglerExe);

		//
		// This is where special options are to be passed. Put your own here as necessary.
		//
		String[] command = new String[] { commandPath.getAbsolutePath(), "-s", "arm" };

		Process process = Runtime.getRuntime().exec(command);

		return process;
	}
}
