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
package ghidra.pdb.pdbreader.type;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.AbstractPdb;
import ghidra.pdb.pdbreader.symbol.AbstractMsSymbol;

/**
 * A class for a specific PDB data type.
 * <P>
 * For more information about PDBs, consult the Microsoft PDB API, see
 * <a href="https://devblogs.microsoft.com/cppblog/whats-inside-a-pdb-file">
 * What's inside a PDB File</a>.
 */
public class ReferencedSymbolMsType extends AbstractMsType {

	public static final int PDB_ID = 0x020c;

	//TODO: Need to see real data to implement correctly.  Just guessing here.  Not sure
	//  if we should search all symbol records to find this "copy," if that is what it really is.
	private AbstractMsSymbol symbolRecord;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException upon error parsing a string.
	 */
	public ReferencedSymbolMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		int recordLength = reader.parseUnsignedShortVal();
		PdbByteReader recordReader = reader.getSubPdbByteReader(recordLength);
		symbolRecord = pdb.getSymbolParser().parse(recordReader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No documented "good" API for output.
		symbolRecord.emit(builder);
	}

}
