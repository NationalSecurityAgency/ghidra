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

import java.io.IOException;
import java.util.Objects;

import ghidra.app.util.bin.format.pdb2.pdbreader.msf.AbstractMsf;
import ghidra.app.util.bin.format.pdb2.pdbreader.msf.MsfParser;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Parser for detecting the appropriate {@link AbstractPdb} for the filename given.
 *  It then creates and returns the appropriate {@link AbstractPdb} object.
 */
public class PdbParser {

	public static final int VC2_ID = 19941610; // 0x013048ea
	public static final int VC4_ID = 19950623; // 0x01306c1f
	public static final int VC41_ID = 19950814; // 0x01306cde
	public static final int VC50_ID = 19960307; // 0x013091f3
	public static final int VC98_ID = 19970604; // 0x0130ba2c
	public static final int VC70DEP_ID = 19990604; // 0x0131084c
	public static final int VC70_ID = 20000404; // 0x01312e94
	public static final int VC80_ID = 20030901; // 0x0131a5b5
	public static final int VC110_ID = 20091201; // 0x01329141
	public static final int VC140_ID = 20140508; // 0x013351dc

	/**
	 * Static method to open a PDB file, determine its version, and return an {@link AbstractPdb}
	 *  appropriate for that version; it will not have been deserialized.  The main method
	 *  to deserialize it is {@link AbstractPdb#deserialize(TaskMonitor monitor)}; the method
	 *  used to deserialize its main identifiers (signature, age, guid (if available)) is
	 *  {@link AbstractPdb#deserializeIdentifiersOnly(TaskMonitor monitor)}.
	 * @param filename {@link String} pathname of the PDB file to parse.
	 * @param pdbOptions {@link PdbReaderOptions} used for processing the PDB.
	 * @param monitor {@link TaskMonitor} used for checking cancellation. 
	 * @return {@link AbstractPdb} class object for the file.
	 * @throws IOException on file I/O issues.
	 * @throws PdbException on parsing issues. 
	 * @throws CancelledException Upon user cancellation.
	 */
	public static AbstractPdb parse(String filename, PdbReaderOptions pdbOptions,
			TaskMonitor monitor) throws IOException, PdbException, CancelledException {
		Objects.requireNonNull(filename, "filename cannot be null");
		Objects.requireNonNull(pdbOptions, "pdbOptions cannot be null");
		Objects.requireNonNull(monitor, "monitor cannot be null");

		// Do not do a try with resources here, as the msf must live within the PDB that is
		//  created below.
		AbstractMsf msf = MsfParser.parse(filename, pdbOptions, monitor);

		int versionNumber = AbstractPdb.deserializeVersionNumber(msf, monitor);

		AbstractPdb pdb;
		switch (versionNumber) {
			case VC2_ID:
				pdb = new Pdb200(msf, pdbOptions);
				break;
			case VC4_ID:
			case VC41_ID:
			case VC50_ID:
			case VC98_ID:
			case VC70DEP_ID:
				pdb = new Pdb400(msf, pdbOptions);
				break;
			case VC70_ID:
			case VC80_ID:
			case VC110_ID:
			case VC140_ID:
				pdb = new Pdb700(msf, pdbOptions);
				break;
			default:
				// Must close the MSF here.  In cases where PDB is created, the PDB takes
				//  responsibility for closing the MSF.
				msf.close();
				throw new PdbException("Unknown PDB Version: " + versionNumber);
		}
		pdb.deserializeIdentifiersOnly(monitor);
		return pdb;
	}

}
