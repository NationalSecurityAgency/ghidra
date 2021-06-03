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
package ghidra.app.util.bin.format.pdb2.pdbreader.symbol;

import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbByteReader;

//TODO: MSFT does not give API.  Need to see real data to fill in the details.
/**
 * This class represents the 2005 version of Defined Single Address Range symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class DefinedSingleAddressRange2005MsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x1134;

	// API does not define whatever data is here.  Just capturing the bytes.
	private byte[] bytes;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 */
	public DefinedSingleAddressRange2005MsSymbol(AbstractPdb pdb, PdbByteReader reader) {
		super(pdb, reader);
		//System.out.println(reader.dump(0x200));
		// TODO: MSFT does not give API.  Need to see real data to fill in the details.
		bytes = reader.parseBytesRemaining();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder) {
		// TODO: MSFT does not give API.  Need to see real data to fill in the details.
		builder.append(
			String.format("%s: <NO API DETAILS, %d BYTES>", getSymbolTypeName(), bytes.length));
	}

	@Override
	protected String getSymbolTypeName() {
		return "DEFRAMGE_2005";
	}

}
