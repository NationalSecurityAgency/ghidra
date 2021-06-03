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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.util.Objects;

/**
 * This class is the version of {@link AbstractModuleInformation} for Microsoft v6.00 PDB.
 */
public class ModuleInformation600 extends AbstractModuleInformation {

	//==============================================================================================
	// Internals
	//==============================================================================================
	private AbstractPdb pdb;

	//==============================================================================================
	// API
	//==============================================================================================
	public ModuleInformation600(AbstractPdb pdb) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
		sectionContribution = new SectionContribution600();
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	@Override
	protected void parseAdditionals(PdbByteReader reader) throws PdbException {
		ecSymbolicInformationEnabled = ((spare & 0x01) == 0x01);
		spare >>= 1;
		nameIndexSourceFile = reader.parseUnsignedIntVal();
		nameIndexCompilerPdbPath = reader.parseUnsignedIntVal();
		moduleName =
			reader.parseNullTerminatedString(pdb.getPdbReaderOptions().getOneByteCharset());
		objectFileName =
			reader.parseNullTerminatedString(pdb.getPdbReaderOptions().getOneByteCharset());
	}

	@Override
	protected String dumpAdditionals() {
		StringBuilder builder = new StringBuilder();
		builder.append("\nnameIndexSourceFile: ");
		builder.append(nameIndexSourceFile);
		builder.append("\nnameIndexCompilerPdbPath: ");
		builder.append(nameIndexCompilerPdbPath);
		return builder.toString();
	}

}
