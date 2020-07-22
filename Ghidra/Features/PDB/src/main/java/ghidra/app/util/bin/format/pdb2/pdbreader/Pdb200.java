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
import java.io.Writer;

import ghidra.app.util.bin.format.pdb2.pdbreader.msf.AbstractMsf;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class is the version of {@link AbstractPdb} for Microsoft v2.00 PDB.
 */
public class Pdb200 extends AbstractPdb {

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Constructor.
	 * @param msf {@link AbstractMsf} foundation for the PDB.
	 * @param pdbOptions {@link PdbReaderOptions} used for processing the PDB.
	 * @throws IOException Upon file IO seek/read issues.
	 * @throws PdbException Upon unknown value for configuration or error in processing components.
	 */
	Pdb200(AbstractMsf msf, PdbReaderOptions pdbOptions) throws IOException, PdbException {
		super(msf, pdbOptions);
	}

	@Override
	void deserializeIdentifiersOnly(TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {
		PdbByteReader reader = getDirectoryReader(monitor);
		deserializeVersionSignatureAge(reader);
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	@Override
	void deserializeDirectory(TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {
		PdbByteReader reader = getDirectoryReader(monitor);
		deserializeVersionSignatureAge(reader);
	}

	@Override
	public void dumpDirectory(Writer writer) throws IOException {
		StringBuilder builder = new StringBuilder();
		builder.append(dumpVersionSignatureAge());
		writer.write(builder.toString());
	}

}
