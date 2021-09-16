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
package ghidra.app.util.pdb;

import ghidra.app.util.bin.format.pdb.PdbParserConstants;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

/**
 * Storage of PDB-related attributes
 */
public class PdbProgramAttributes {

	private String pdbAge; // hex format
	private String pdbGuid;
	private String pdbSignature;

	private String pdbFile;
	private String pdbVersion;
	private boolean pdbLoaded;
	private boolean programAnalyzed;
	private String executablePath;

	public PdbProgramAttributes(Program program) {

		Options propList = program.getOptions(Program.PROGRAM_INFO);

		pdbGuid = propList.contains(PdbParserConstants.PDB_GUID)
				? propList.getString(PdbParserConstants.PDB_GUID, null)
				: null;
		pdbAge = propList.contains(PdbParserConstants.PDB_AGE)
				? propList.getString(PdbParserConstants.PDB_AGE, null)
				: null;
		pdbLoaded = propList.contains(PdbParserConstants.PDB_LOADED)
				? propList.getBoolean(PdbParserConstants.PDB_LOADED, false)
				: false;
		programAnalyzed = propList.contains(Program.ANALYZED)
				? propList.getBoolean(Program.ANALYZED, false)
				: false;
		pdbSignature = propList.contains(PdbParserConstants.PDB_SIGNATURE)
				? propList.getString(PdbParserConstants.PDB_SIGNATURE, null)
				: null;
		pdbFile = propList.contains(PdbParserConstants.PDB_FILE)
				? propList.getString(PdbParserConstants.PDB_FILE, null)
				: null;
		pdbVersion = propList.contains(PdbParserConstants.PDB_VERSION)
				? propList.getString(PdbParserConstants.PDB_VERSION, null)
				: null;

		executablePath = program.getExecutablePath();
	}

	// Used for testing purposes to make a "dummy" object 
	public PdbProgramAttributes(String guid, String age, boolean loaded, boolean analyzed,
			String signature, String file, String execPath) {
		pdbGuid = guid;
		pdbAge = age;
		pdbLoaded = loaded;
		programAnalyzed = analyzed;
		pdbSignature = signature;
		pdbFile = file;
		pdbVersion = "RSDS"; // TODO: possibly receive this as argument.

		executablePath = execPath;
	}

	/**
	 * PDB Age as a hex value
	 * @return PDB Age as a hex value
	 */
	public String getPdbAge() {
		return pdbAge;
	}

	/**
	 * Returns the decoded integer value of the age string.
	 * 
	 * @return int value of age string, or 0 if invalid or undefined
	 */
	public int getPdbAgeAsInt() {
		try {
			return Integer.parseInt(pdbAge, 16);
		}
		catch (NumberFormatException e) {
			return 0;
		}
	}

	public String getPdbGuid() {
		return pdbGuid;
	}

	public String getPdbSignature() {
		return pdbSignature;
	}

	/**
	 * Returns the decoded integer value of the signature string.
	 * 
	 * @return int value of signature string, or 0 if invalid or undefined
	 */
	public int getPdbSignatureAsInt() {
		try {
			return Integer.parseUnsignedInt(pdbSignature, 16);
		}
		catch (NumberFormatException e) {
			return 0;
		}
	}

	public String getPdbFile() {
		return pdbFile;
	}

	public String getPdbVersion() {
		return pdbVersion;
	}

	public boolean isPdbLoaded() {
		return pdbLoaded;
	}

	public String getExecutablePath() {
		return executablePath;
	}

	public boolean isProgramAnalyzed() {
		return programAnalyzed;
	}


}
