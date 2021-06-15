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

/**
 * There is no documentation for this symbol in the current API.  This symbol was not seen,
 *  but 1167 and 1168 were seen with a VS2017 compile.  Guessing there is likely a 1166 symbol.
 */
public class UnknownX1166MsSymbol extends AbstractUnknownMsSymbol {

	public static final int PDB_ID = 0x1166;

	private byte[] data;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 */
	public UnknownX1166MsSymbol(AbstractPdb pdb, PdbByteReader reader) {
		super(pdb, reader);
		data = reader.parseBytesRemaining();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the data of this symbol (we do not know how to interpret it yet).
	 * @return {@code byte[]} data.
	 */
	public byte[] getData() {
		return data;
	}

	@Override
	public void emit(StringBuilder builder) {
		PdbByteReader reader = new PdbByteReader(data);
		builder.append(String.format("%s: Bytes:%s", getSymbolTypeName(), reader.dumpBytes()));
	}

	@Override
	protected String getSymbolTypeName() {
		return "UNKNOWN_SYMBOL_X1166";
	}

}
