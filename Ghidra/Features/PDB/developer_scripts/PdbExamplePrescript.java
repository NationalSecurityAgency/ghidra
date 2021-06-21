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
//Example preScript to force a PdbAnalyzer to use a custom PDB
//symbol file when analyzing a binary.
//@category PDB
import java.io.File;

import ghidra.app.plugin.core.analysis.PdbAnalyzer;
import ghidra.app.script.GhidraScript;

public class PdbExamplePrescript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		// contrived example of choosing a pdb file with custom logic
		File pdbFile = new File(getProgramFile().getPath() + ".pdb");

		PdbAnalyzer.setPdbFileOption(currentProgram, pdbFile);
		// or
		//PdbUniversalAnalyzer.setPdbFileOption(currentProgram, pdbFile);
	}
}
