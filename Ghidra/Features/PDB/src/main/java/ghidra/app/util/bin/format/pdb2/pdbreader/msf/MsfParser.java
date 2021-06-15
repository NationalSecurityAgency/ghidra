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
package ghidra.app.util.bin.format.pdb2.pdbreader.msf;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Objects;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Parser for detecting the appropriate {@link AbstractMsf} format for the filename given.
 *  It then creates and returns the appropriate {@link AbstractMsf} object.
 */
public class MsfParser {

	/**
	 * Detects, creates, and returns the appropriate {@link AbstractMsf} object found for
	 * the filename given. 
	 * @param filename Filename of the file to process.
	 * @param pdbOptions {@link PdbReaderOptions} used for processing the PDB.
	 * @param monitor {@link TaskMonitor} used for checking cancellation. 
	 * @return Derived {@link AbstractMsf} object.
	 * @throws IOException For file I/O reasons
	 * @throws PdbException If an appropriate object cannot be created.
	 * @throws CancelledException Upon user cancellation.
	 */
	public static AbstractMsf parse(String filename, PdbReaderOptions pdbOptions,
			TaskMonitor monitor) throws IOException, PdbException, CancelledException {
		Objects.requireNonNull(filename, "filename cannot be null");
		Objects.requireNonNull(pdbOptions, "pdbOptions cannot be null");
		Objects.requireNonNull(monitor, "monitor cannot be null");

		AbstractMsf msf;
		RandomAccessFile file = new RandomAccessFile(filename, "r");
		if (Msf200.detected(file)) {
			msf = new Msf200(file, pdbOptions);
		}
		else if (Msf700.detected(file)) {
			msf = new Msf700(file, pdbOptions);
		}
		else {
			// Must close the file here.  In cases where MSF is created, the MSF takes
			//  responsibility for closing the file.
			file.close();
			throw new PdbException("MSF format not detected");
		}
		msf.deserialize(monitor);
		return msf;
	}

}
