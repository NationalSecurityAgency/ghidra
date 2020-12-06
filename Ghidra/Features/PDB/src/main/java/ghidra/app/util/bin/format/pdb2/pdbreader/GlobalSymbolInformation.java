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

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class represents Global Symbol Information component of a PDB file.  This class is only
 *  suitable for reading; not for writing or modifying a PDB.
 *  <P>
 *  We have intended to implement according to the Microsoft PDB API (source); see the API for
 *   truth.
 *   @see AbstractSymbolInformation
 *   @see PublicSymbolInformation
 */
public class GlobalSymbolInformation extends AbstractSymbolInformation {

	/**
	 * Constructor.
	 * @param pdbIn {@link AbstractPdb} that owns the Global Symbol Information to process.
	 */
	public GlobalSymbolInformation(AbstractPdb pdbIn) {
		super(pdbIn);
	}

	/**
	 * Deserialize the {@link GlobalSymbolInformation} from the appropriate stream in the Pdb.
	 * @param streamNumber the stream number containing the information to deserialize.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	@Override
	void deserialize(int streamNumber, TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {
		super.deserialize(streamNumber, monitor);
		PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber, monitor);
		deserializeHashTable(reader, monitor);

		// Organize the information
		generateSymbolsList(monitor);
	}

	/**
	 * Debug method for dumping information from this {@link GlobalSymbolInformation}.
	 * @param writer {@link Writer} to which to dump the information.
	 * @throws IOException Upon IOException writing to the {@link Writer}.
	 */
	@Override
	void dump(Writer writer) throws IOException {
		StringBuilder builder = new StringBuilder();
		builder.append("GlobalSymbolInformation-------------------------------------\n");
		dumpHashHeader(builder);
		dumpHashBasics(builder);
		dumpHashRecords(builder);
		builder.append("\nEnd GlobalSymbolInformation---------------------------------\n");
		writer.write(builder.toString());
	}

}
