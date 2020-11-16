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

import ghidra.app.util.datatype.microsoft.GUID;

/**
 * This class holds fields used to identify a PDB.
 * <P>
 * These are Version, Signature, Age, and GUID. Som identifiers can be null if not found in
 * the specific version of the PDB. 
 */
public class PdbIdentifiers {

	private final int version;
	private final int signature;
	private final int age;
	private final GUID guid;
	private final Processor processor;

	/**
	 * Constructor.
	 * @param version The version number.
	 * @param signature The signature.
	 * @param age age used to verify PDB against age stored in program
	 * @param guid The GUID (can be null for older PDBs).
	 */
	PdbIdentifiers(int version, int signature, int age, GUID guid, Processor processor) {
		this.version = version;
		this.signature = signature;
		this.age = age;
		this.guid = guid;
		this.processor = processor == null ? Processor.UNKNOWN : processor;
	}

	/**
	 * Returns the Version Number of the PDB.
	 * @return Version Number of the PDB.
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * Returns the Signature of the PDB.
	 * @return Signature of the PDB.
	 */
	public int getSignature() {
		return signature;
	}

	/**
	 * Returns the Age of the PDB.
	 * @return Age of the PDB.
	 */
	public int getAge() {
		return age;
	}

	/**
	 * Returns the GUID for the PDB.
	 * @return {@link GUID} for the PDB.
	 */
	public GUID getGuid() {
		return guid;
	}

}
