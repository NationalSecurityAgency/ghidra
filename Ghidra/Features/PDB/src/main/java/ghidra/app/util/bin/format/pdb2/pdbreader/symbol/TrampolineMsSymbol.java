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
 * This class represents the Trampoline symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class TrampolineMsSymbol extends AbstractMsSymbol implements AddressMsSymbol {

	public static final int PDB_ID = 0x112c;

	public enum Type {

		UNKNOWN("<unknown subtype>", -1),
		INCREMENTAL("Incremental", 0),
		BRANCH_ISLAND("BranchIsland", 1);

		private static final Map<Integer, Type> BY_VALUE = new HashMap<>();
		static {
			for (Type val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String label;
		public final int value;

		@Override
		public String toString() {
			return label;
		}

		public static Type fromValue(int val) {
			return BY_VALUE.getOrDefault(val, UNKNOWN);
		}

		private Type(String label, int value) {
			this.label = label;
			this.value = value;
		}
	}

	//==============================================================================================
	private Type trampolineType;
	private int sizeOfThunk;
	private long offsetThunk;
	private long offsetTarget;
	private int sectionThunk;
	private int sectionTarget;

	//==============================================================================================
	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public TrampolineMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		trampolineType = Type.fromValue(reader.parseUnsignedShortVal());
		sizeOfThunk = reader.parseUnsignedShortVal();
		offsetThunk = reader.parseUnsignedIntVal();
		offsetTarget = reader.parseUnsignedIntVal();
		// Not sure if sectionThunk and sectionTarget are really "segment."  We are using later
		//  in TramplineSymbolApplier in a call to reladdr(), so we believe they are segments.
		sectionThunk = pdb.parseSegment(reader);
		sectionTarget = pdb.parseSegment(reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the {@link Type} of trampoline.
	 * @return The {@link Type} of trampoline.
	 */
	public Type getType() {
		return trampolineType;
	}

	/**
	 * Returns size of thunk.
	 * @return Size of thunk.
	 */
	public int getSizeOfThunk() {
		return sizeOfThunk;
	}

	@Override
	public long getOffset() {
		return getOffsetThunk();
	}

	@Override
	public int getSegment() {
		return getSegmentThunk();
	}

	/**
	 * Returns offset of thunk.
	 * @return Offset of thunk.
	 */
	public long getOffsetThunk() {
		return offsetThunk;
	}

	/**
	 * Returns offset of target.
	 * @return Offset of target.
	 */
	public long getOffsetTarget() {
		return offsetTarget;
	}

	/**
	 * Returns segment (MSFT says section) of thunk.
	 * @return Segment (MSFT says section) of thunk.
	 */
	public int getSegmentThunk() {
		return sectionThunk;
	}

	/**
	 * Returns segment (MSFT says section) of target.
	 * @return Segment (MSFT says section) of target.
	 */
	public int getSegmentTarget() {
		return sectionTarget;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		builder.append(": subtype ");
		builder.append(trampolineType);
		builder.append(String.format(", code size = %d bytes\n", sizeOfThunk));
		builder.append(String.format("   Thunk address: [%04X:%08X]\n", sectionThunk, offsetThunk));
		builder.append(
			String.format("   Thunk target:  [%04X:%08X]\n", sectionTarget, offsetTarget));
	}

	@Override
	protected String getSymbolTypeName() {
		return "TRAMPOLINE";
	}

}
