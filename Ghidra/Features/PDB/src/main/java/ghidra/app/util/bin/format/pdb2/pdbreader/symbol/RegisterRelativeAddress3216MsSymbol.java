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
 * This class represents the <B>3216MsSymbol</B> flavor of Register Relative Address symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class RegisterRelativeAddress3216MsSymbol extends AbstractRegisterRelativeAddressMsSymbol {

	public static final int PDB_ID = 0x020c;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public RegisterRelativeAddress3216MsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		offset = reader.parseVarSizedOffset(32);
		registerIndex = reader.parseUnsignedShortVal();
		typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 16);
		name = reader.parseString(pdb, StringParseType.StringUtf8St);
		reader.align4();
		registerName = new RegisterName(pdb, registerIndex);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	protected String getSymbolTypeName() {
		return "REGREL32_16";
	}

}
