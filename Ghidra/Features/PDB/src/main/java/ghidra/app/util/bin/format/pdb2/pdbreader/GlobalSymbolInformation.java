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

import ghidra.app.util.bin.format.pdb2.pdbreader.msf.MsfStream;
import ghidra.util.exception.CancelledException;

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
	 * @param streamNumber the stream number containing the symbol information
	 */
	public GlobalSymbolInformation(AbstractPdb pdbIn, int streamNumber) {
		super(pdbIn, streamNumber);
	}

	/**
	 * Deserializes and intializes {@link GlobalSymbolInformation} basic information from the
	 * appropriate stream in the Pdb so that later queries can be made
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	@Override
	void initialize() throws IOException, PdbException, CancelledException {
		initializeValues();
		initializeGlobalOffsetsAndLengths();
		deserializeHashHeader();
	}

	private void initializeGlobalOffsetsAndLengths() {
		symbolHashOffset = 0;
		MsfStream stream = pdb.getMsf().getStream(streamNumber);
		symbolHashLength = (stream == null) ? 0 : stream.getLength();
	}

	/**
	 * Debug method for dumping information from this {@link GlobalSymbolInformation}
	 * @param writer {@link Writer} to which to dump the information
	 * @throws IOException issue reading PDBor upon issue writing to the {@link Writer}
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon not enough data left to parse
	 */
	@Override
	void dump(Writer writer) throws IOException, CancelledException, PdbException {
		StringBuilder builder = new StringBuilder();
		builder.append("GlobalSymbolInformation-------------------------------------\n");
		dumpHashHeader(builder);
		dumpHashBasics(builder);
		dumpHashRecords(builder);
		builder.append("\nEnd GlobalSymbolInformation---------------------------------\n");
		writer.write(builder.toString());
	}

}
