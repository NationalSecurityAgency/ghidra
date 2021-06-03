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

import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents the Arm Switch Table symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class ArmSwitchTableMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x1159;

	public enum EntryType {

		UNKNOWN("unknown return", -1),
		INT1("signed byte", 0),
		UINT1("unsigned byte", 1),
		INT2("signed two byte", 2),
		UINT2("unsigned two byte", 3),
		INT4("signed four byte", 4),
		UINT4("unsigned four byte", 5),
		POINTER("pointer", 6),
		UINT1SHL1("unsigned byte scaled by two", 7),
		UINT2SHL1("unsigned two byte scaled by two", 8),
		INT1SHL1("signed byte scaled by two", 9),
		INT2SHL1("signed two byte scaled by two", 10);

		private static final Map<Integer, EntryType> BY_VALUE = new HashMap<>();
		static {
			for (EntryType val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String label;
		public final int value;

		@Override
		public String toString() {
			return label;
		}

		public static EntryType fromValue(int val) {
			return BY_VALUE.getOrDefault(val, UNKNOWN);
		}

		private EntryType(String label, int value) {
			this.label = label;
			this.value = value;
		}
	}

	//==============================================================================================
	private long offsetToBaseForSwitchOffsets;
	private int sectionIndexOfBaseForSwitchOffsets;
	private EntryType switchType;
	private long offsetToTableBranchInstruction;
	private long offsetToStartOfTable;
	private int sectionIndexOfTableBranchInstruction;
	private int sectionIndexOfTable;
	private long numberOfSwitchTableEntries;

	//==============================================================================================
	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public ArmSwitchTableMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		offsetToBaseForSwitchOffsets = reader.parseVarSizedOffset(32);
		sectionIndexOfBaseForSwitchOffsets = pdb.parseSegment(reader);
		switchType = EntryType.fromValue(reader.parseUnsignedShortVal());
		offsetToTableBranchInstruction = reader.parseVarSizedOffset(32);
		offsetToStartOfTable = reader.parseVarSizedOffset(32);
		sectionIndexOfTableBranchInstruction = pdb.parseSegment(reader);
		sectionIndexOfTable = pdb.parseSegment(reader);
		numberOfSwitchTableEntries = reader.parseUnsignedIntVal();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the {@link EntryType}.
	 * @return The {@link EntryType}.
	 */
	public EntryType getSwitchEntryType() {
		return switchType;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		builder.append(":\n");
		builder.append(String.format("   Base address:   [%04X:%08X]\n",
			sectionIndexOfBaseForSwitchOffsets, offsetToBaseForSwitchOffsets));
		builder.append(String.format("   Branch address: [%04X:%08X]\n",
			sectionIndexOfTableBranchInstruction, offsetToTableBranchInstruction));
		builder.append(String.format("   Table address:  [%04X:%08X]\n", sectionIndexOfTable,
			offsetToStartOfTable));
		builder.append(String.format("   Entry count = %d\n", numberOfSwitchTableEntries));
		builder.append("   Switch entry type = " + switchType + "\n");
	}

	@Override
	protected String getSymbolTypeName() {
		return "ARMSWITCHTABLE";
	}

}
