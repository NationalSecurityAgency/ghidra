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
//This script extracts DWARF 2, 3, or 4 debug information
//and applies it to the program.
//
// This script reads DWARF information from the debug sections of a binary and
// imports the information into Ghidra.
// This information includes: data type definitions, namespace and class information,
// function signatures, and function source file locations.
// Currently, the script is based off of DWARF2, DWARF3, and DWARF4 specification. However,
// not all features or possibilities have been implemented.
// The default max of 512MB RAM allocated for Ghidra is not enough for running the
// script on larger binaries. Setting -Xmx2g should be sufficient.
//
// Features that still require implementing:
// - All TAG data types have not yet been implemented. This script will not complete if
//     it encounters an unknown data type and that data type is used.
// - Location description processing is currently hardcoded for the most common expressions.
//     This should be updated to support any valid location description.
// - Expression description processing is incomplete. All description opcodes should be supported.
// - Location description and Expression description should probably be set up similiar
//     to frysk (see frysk-core/frysk/debuginfo/LocationExpression.java)
// - Handle all errors correctly, setup warning/error system to print out or log
//     warnings/errors while processing
// - Program tree currently does not allow any duplicate names
// - Match all datatypes found by the demangler with datatypes processed in DWARF
// - Various testing and fixes on a variety of different compiled binaries
//
//
// Possible Future Improvements:
// - Create a custom data type manager to handle adding datatypes temporarily
// - Only add datatypes to Ghidra's data type manager after all data types have been processed
// - Increase speed of the script as most of the waiting involves waiting on adding
//     data types to Ghidra's data type manager
// - Remove any hacks that are currently necessary for the script to add and use data types correctly
// - Possibility to add data types to a subfolder based on namespace or class during data
//     type processing
// - Check source language type and look for certain language constructs while processing
//
//
//@author User Submitted - based on DWARF_script.java
//@category Binary
//

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.dwarf4.next.*;
import ghidra.program.model.data.BuiltInDataTypeManager;

public class DWARF_ExtractorScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (!DWARFProgram.isDWARF(currentProgram)) {
			popup("Unable to find DWARF information, aborting");
			return;
		}
		DWARFImportOptions importOptions = new DWARFImportOptions();
		importOptions.setImportLimitDIECount(Integer.MAX_VALUE);
		try (DWARFProgram dwarfProg = new DWARFProgram(currentProgram, importOptions, monitor)) {
			BuiltInDataTypeManager dtms = BuiltInDataTypeManager.getDataTypeManager();
			DWARFParser dp = new DWARFParser(dwarfProg, dtms, monitor);
			DWARFImportSummary importSummary = dp.parse();
			importSummary.logSummaryResults();
		}
	}
}
