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

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * There is no documentation for this symbol in the current API.  This symbol was seen with a
 *  VS2017 compile.
 */
public class UnknownX1167MsSymbol extends AbstractUnknownMsSymbol {

	public static final int PDB_ID = 0x1167;

	// We have no idea about the structure, though unsigned short values and a string
	//  seem to be seen.
	private int unknownUnsignedShort1;
	private int unknownUnsignedShort2;
	private int unknownUnsignedShort3;
	private String string;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public UnknownX1167MsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		unknownUnsignedShort1 = reader.parseUnsignedShortVal();
		unknownUnsignedShort2 = reader.parseUnsignedShortVal();
		unknownUnsignedShort3 = reader.parseUnsignedShortVal();
		string = reader.parseString(pdb, StringParseType.StringUtf8Nt);
		reader.align4();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the value what appears to be the first Unsigned Short.
	 * @return Value in what appears to be first unsigned short.
	 */
	public int getUnknownUnsignedShort1() {
		return unknownUnsignedShort1;
	}

	/**
	 * Returns the value what appears to be the second Unsigned Short.
	 * @return Value in what appears to be second unsigned short.
	 */
	public int getUnknownUnsignedShort2() {
		return unknownUnsignedShort2;
	}

	/**
	 * Returns the value what appears to be the third Unsigned Short.
	 * @return Value in what appears to be third unsigned short.
	 */
	public int getUnknownUnsignedShort3() {
		return unknownUnsignedShort3;
	}

	/**
	 * Returns what appears to be String data after the Unsigned Short fields.
	 * @return What appears to be a string after the unsigned short fields.
	 */
	public String getStringData() {
		return string;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		builder.append(String.format("\nunknownUnsignedShort1: %04X", unknownUnsignedShort1));
		builder.append(String.format("\nunknownUnsignedShort2: %04X", unknownUnsignedShort2));
		builder.append(String.format("\nunknownUnsignedShort3: %04X", unknownUnsignedShort3));
		builder.append(String.format("\nString: %s", getStringData()));
	}

	@Override
	protected String getSymbolTypeName() {
		return "UNKNOWN_SYMBOL_X1167";
	}

}
