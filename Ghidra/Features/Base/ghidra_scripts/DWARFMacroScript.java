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
// Parses the .debug_macro section of a file with DWARF debug info (version 5+) and 
// prints the result to the ghidra console.
// @category DWARF

import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.dwarf.*;
import ghidra.app.util.bin.format.dwarf.macro.DWARFMacroHeader;
import ghidra.app.util.bin.format.dwarf.macro.entry.*;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProvider;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProviderFactory;

public class DWARFMacroScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		DWARFSectionProvider dsp =
			DWARFSectionProviderFactory.createSectionProviderFor(currentProgram, monitor);
		if (dsp == null) {
			printerr("Unable to find DWARF information");
			return;
		}

		try (DWARFProgram dprog =
			new DWARFProgram(currentProgram, new DWARFImportOptions(), monitor, dsp)) {
			dprog.init(monitor);
			for (DWARFCompilationUnit cu : dprog.getCompilationUnits()) {
				dumpMacros(cu.getMacros(), 0);
			}
		}
	}

	void dumpMacros(DWARFMacroHeader macroHeader, int indent) throws IOException {
		for (DWARFMacroInfoEntry macroEntry : macroHeader.getEntries()) {
			print(macroEntry.toString().indent(indent));
			switch (macroEntry) {
				case DWARFMacroImport macroImport:
					dumpMacros(macroImport.getImportedMacroHeader(), indent + 2);
					break;
				case DWARFMacroStartFile macroStartFile:
					indent += 2;
					break;
				case DWARFMacroEndFile macroEndFile:
					indent -= 2;
					break;
				default:
			}
		}
	}

}
