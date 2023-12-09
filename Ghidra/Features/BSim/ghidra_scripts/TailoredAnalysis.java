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
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

// Setup tailored auto-analysis (in place of the headless analyzers full auto-analysis)
// suitable for BSim ingest process.  Intended to be invoked as an analyzeHeadless -preScript
//@category BSim

//note: script mentioned in BSim documentation by name
public class TailoredAnalysis extends GhidraScript {

	@Override
	public void run() throws Exception {
		Options pl = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
		pl.setBoolean("Decompiler Parameter ID", false);

		// These analyzers generate lots of cross references, which are not necessary for
		// signature analysis, and take time to run.  On the other hand, you may want
		// them in general to facilitate general analysis
		pl.setBoolean("Stack", false);
//		pl.setBoolean("Windows x86 PE Instruction References", false);
//		pl.setBoolean("Windows x86 PE C++", false);
//		pl.setBoolean("Windows x86 PE Preliminary", false);
//        pl.setBoolean("ELF Scalar Operand References", false);

		// Mangled symbols are good information but you may not be able to count on them being present in all versions
//      Options analyzerOptions = pl.getOptions("Demangler");
//      analyzerOptions.setBoolean("Commit Function Signatures", false);

		// You really want these options turned on
		pl.setBoolean("Shared Return Calls", true);
		pl.setBoolean("Function Start Search", true);

		//The DWARF analyzer can take a long time, so for mass ingest it might be worth
		//turning it off
		//Moreover, the DWARF analyzer can lock prototypes, which can change the BSim signature
		//of a function.  This can negatively impact matches between executables with DWARF 
		//and executables without it.
		pl.setBoolean("DWARF", false);
//        Options analyzerOptions = pl.getOptions("Function Start Search");
//        analyzerOptions.setBoolean("Search Data Blocks", true);
//        analyzerOptions = pl.getOptions("Function Start Search After Code");
//        analyzerOptions.setBoolean("Search Data Blocks", true);
//        analyzerOptions = pl.getOptions("Function Start Search After Data");
//        analyzerOptions.setBoolean("Search Data Blocks", true);
	}

}
