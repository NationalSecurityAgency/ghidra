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
package ghidra.pdb.pdbreader;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;

/**
 * This class is the version of {@link AbstractModuleInformation} for Microsoft v5.00 PDB.
 */
public class ModuleInformation500 extends AbstractModuleInformation {

	//==============================================================================================
	// API
	//==============================================================================================
	public ModuleInformation500() {
		sectionContribution = new SectionContribution400();
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	@Override
	protected void parseAdditionals(PdbByteReader reader) throws PdbException {
		ecSymbolicInformationEnabled = false;
		nameIndexSourceFile = 0; // no value available.
		nameIndexCompilerPdbPath = 0; // no value available.
		moduleName = reader.parseNullTerminatedString();
		objectFileName = reader.parseNullTerminatedString();
	}

	@Override
	protected String dumpAdditionals() {
		return "";
	}

}
