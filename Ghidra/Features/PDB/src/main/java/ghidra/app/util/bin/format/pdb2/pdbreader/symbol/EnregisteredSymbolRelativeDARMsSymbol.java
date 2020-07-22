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
 * This class represents the Defined Singled Address Range For Enregistered Symbols Relative symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class EnregisteredSymbolRelativeDARMsSymbol
		extends AbstractDefinedSingleAddressRangeMsSymbol {

	public static final int PDB_ID = 0x1145;

	private int baseRegister;
	private RegisterName baseRegisterName;
	private boolean isSpilledUserDefinedTypeMember;
	private int offsetInParent;
	private int offsetToBaseRegister;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public EnregisteredSymbolRelativeDARMsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		baseRegister = reader.parseUnsignedShortVal();
		baseRegisterName = new RegisterName(pdb, baseRegister);
		int fields = reader.parseUnsignedShortVal();
		isSpilledUserDefinedTypeMember = ((fields & 0x0001) == 0x0001);
		fields >>= 4; // Skipping 3 padding bits too.
		offsetInParent = fields & 0x0fff;
		offsetToBaseRegister = reader.parseInt(); //signed
		parseRangeAndGaps(reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	protected String getSymbolTypeName() {
		return "DEFRANGE_REGISTER_REL";
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		builder.append(
			String.format(": [%s + %04X]", baseRegisterName.toString(), offsetToBaseRegister));
		if (isSpilledUserDefinedTypeMember) {
			builder.append(
				String.format(" spilledUserDefinedTypeMember offset at %d", offsetInParent));
		}
		emitRangeAndGaps(builder);
	}

}
