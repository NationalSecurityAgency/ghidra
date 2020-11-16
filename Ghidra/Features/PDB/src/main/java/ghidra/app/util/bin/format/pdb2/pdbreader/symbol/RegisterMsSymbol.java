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
 * This class represents the <B>MsSymbol</B> flavor of Register symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class RegisterMsSymbol extends AbstractRegisterMsSymbol {

	public static final int PDB_ID = 0x1106;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public RegisterMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader, 32, StringParseType.StringUtf8Nt);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	protected RegisterName parseRegister(PdbByteReader reader) throws PdbException {
		return new RegisterName(pdb, reader.parseUnsignedShortVal());
	}

	@Override
	protected void emitRegisterInformation(StringBuilder builder) {
		register.emit(builder);
	}

	@Override
	protected String getSymbolTypeName() {
		return "REGISTER";
	}

}
