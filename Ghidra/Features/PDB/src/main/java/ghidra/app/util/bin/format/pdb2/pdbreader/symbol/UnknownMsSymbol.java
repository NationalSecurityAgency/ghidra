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
 * This is not a real MS Symbol.  We made this up to take the place of anticipated, unknown
 *  symbols.
 */
public class UnknownMsSymbol extends AbstractUnknownMsSymbol {

	private int unknownPdbId = 0;
	private byte[] data;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @param unknownPdbId Value to be used as the unique PDB ID.
	 */
	public UnknownMsSymbol(AbstractPdb pdb, PdbByteReader reader, int unknownPdbId) {
		super(pdb, reader);
		this.unknownPdbId = unknownPdbId;
		data = reader.parseBytesRemaining();
	}

	@Override
	public int getPdbId() {
		return unknownPdbId;
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
		return String.format("UNKNOWN_SYMBOL (0X%04X)", unknownPdbId);
	}

}
