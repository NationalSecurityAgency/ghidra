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
package ghidra.app.util.bin.format.pdb2.pdbreader.type;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.util.exception.CancelledException;

/**
 * This class represents the <B>MsType</B> flavor of Referenced Symbol type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
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
	 * @throws CancelledException Upon user cancellation.
	 */
	public ReferencedSymbolMsType(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException, CancelledException {
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
