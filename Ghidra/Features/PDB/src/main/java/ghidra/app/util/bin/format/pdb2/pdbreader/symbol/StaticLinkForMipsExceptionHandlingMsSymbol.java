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
 * This class represents the Static Link Fro MIPS Exception Handling symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class StaticLinkForMipsExceptionHandlingMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x020f;

	private long framesize;
	private long offset;
	private int register;
	private RegisterName registerName;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public StaticLinkForMipsExceptionHandlingMsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		framesize = reader.parseUnsignedIntVal();
		offset = reader.parseInt();
		register = reader.parseUnsignedShortVal();
		registerName = new RegisterName(pdb, register);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: framesize = %08X, offset = %08X, register = %s",
			getSymbolTypeName(), framesize, offset, registerName.toString()));
	}

	@Override
	protected String getSymbolTypeName() {
		return "SLINK32";
	}

}
