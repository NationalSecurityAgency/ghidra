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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.datatype.microsoft.GUID;

/**
 * This class represents the OEM-Defined symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class OemDefinedMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x0404;

	private static final byte[] guidPartSSOEMID =
		{ (byte) 0xbc, 0x25, 0x09, 0x02, (byte) 0xbb, (byte) 0xab, (byte) 0xb4, 0x60 };
	private static final GUID SSOEMID =
		new GUID(0xc6ea3fc9, (short) 0x59b3, (short) 0x49d6, guidPartSSOEMID);

	//==============================================================================================
	private GUID oemID;
	private RecordNumber typeRecordNumber;
	private List<Long> userData = new ArrayList<>();

	//==============================================================================================
	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public OemDefinedMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		int data1 = reader.parseInt();
		short data2 = reader.parseShort();
		short data3 = reader.parseShort();
		byte[] data4 = reader.parseBytes(8);
		oemID = new GUID(data1, data2, data3, data4);
		typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		while (reader.hasMore()) {
			long val = reader.parseUnsignedIntVal();
			userData.add(val);
		}
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: %s, Type %s\n", getSymbolTypeName(), oemID,
			pdb.getTypeRecord(typeRecordNumber)));
		if (oemID.equals(SSOEMID)) {
			// TODO: is there a name to output?
			for (long val : userData) {
				builder.append(String.format("   %08X\n", val));
			}
		}
	}

	@Override
	protected String getSymbolTypeName() {
		return "OEM";
	}

}
