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
package ghidra.pdb.pdbreader.symbol;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.AbstractPdb;
import ghidra.pdb.pdbreader.RegisterName;

/**
 * This class represents the Defined Singled Address Range For Enregistered Field of Symbols symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class EnregisteredFieldOfSymbolDARMsSymbol
		extends AbstractDefinedSingleAddressRangeMsSymbol {

	public static final int PDB_ID = 0x1143;

	private int registerHoldingValueOfSymbol;
	private RegisterName registerName;
	private RangeAttribute rangeAttribute;
	private int offsetInParent;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public EnregisteredFieldOfSymbolDARMsSymbol(AbstractPdb pdb,
			PdbByteReader reader) throws PdbException {
		super(pdb, reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	protected String getSymbolTypeName() {
		return "DEFRANGE_SUBFIELD_REGISTER";
	}

	@Override
	protected void parseInitialData(PdbByteReader reader) throws PdbException {
		registerHoldingValueOfSymbol = reader.parseUnsignedShortVal();
		registerName = new RegisterName(pdb, registerHoldingValueOfSymbol);
		rangeAttribute = new RangeAttribute(reader);
		long fields = reader.parseUnsignedIntVal();
		offsetInParent = (int) (fields & 0x0fff);
	}

	@Override
	protected void emitInitialData(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		builder.append(String.format(": offset at %04X: ", offsetInParent));
		builder.append(rangeAttribute);
		builder.append(" ");
		builder.append(registerName);
	}

	@Override
	protected void emitFinalData(StringBuilder builder) {
		//Do nothing.
	}

}
