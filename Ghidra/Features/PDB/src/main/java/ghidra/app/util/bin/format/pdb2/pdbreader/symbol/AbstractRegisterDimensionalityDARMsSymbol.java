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
 * This class represents various flavors of Defined Address Range With Register Dimensionality
 *  symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractRegisterDimensionalityDARMsSymbol
		extends AbstractDefinedSingleAddressRangeMsSymbol {

	public enum MemorySpace {

		INVALID("INVALID MEMORY SPACE", -1),
		DATA("DATA", 0),
		SAMPLER("SAMPLER", 1),
		RESOURCE("RESOURCE", 2),
		READWRITERESOURCE("RWRESOURCE", 3);

		private static final Map<Integer, MemorySpace> BY_VALUE = new HashMap<>();
		static {
			for (MemorySpace val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String label;
		public final int value;

		@Override
		public String toString() {
			return label;
		}

		public static MemorySpace fromValue(int val) {
			return BY_VALUE.getOrDefault(val, INVALID);
		}

		private MemorySpace(String label, int value) {
			this.label = label;
			this.value = value;
		}
	}

	//==============================================================================================
	protected int registerType;
	protected RegisterName registerName;
	protected int registerIndices;
	protected boolean isSpilledUserDefinedTypeMember;
	protected MemorySpace memorySpace;
	protected int offsetInParent;
	protected int sizeInParent;
	protected int[] multidimensionalOffsetOfVariableLocationInRegister;

	//==============================================================================================
	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractRegisterDimensionalityDARMsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		registerType = reader.parseUnsignedShortVal();
		registerName = new RegisterName(pdb, registerType);
		int fields = reader.parseUnsignedShortVal();
		registerIndices = fields & 0x0003;
		fields >>= 2;
		isSpilledUserDefinedTypeMember = ((fields & 0x0001) == 0x0001);
		fields >>= 1;
		memorySpace = MemorySpace.fromValue(fields & 0x000f);
		offsetInParent = reader.parseUnsignedShortVal();
		sizeInParent = reader.parseUnsignedShortVal();
		// Number of records:
		//  recordLength (getLimit()):
		//    minus unsigned short record type field: 2 bytes
		//    minus unsigned short register dimensionality: 2 bytes
		//    minus unsigned short bit-fields: 2 bytes
		//    minus unsigned short offsetInParent: 2 bytes
		//    minus unsigned short sizeInParent: 2 bytes
		//    minus registerIndices * (unsigned long dimensionality: 4 bytes) : 0, 4, or 8.
		int numRangeAndGapsBytes = (reader.getLimit() - 10 - (registerIndices * 4));
		PdbByteReader rangeAndGapsReader = reader.getSubPdbByteReader(numRangeAndGapsBytes);
		super.parseRangeAndGaps(rangeAndGapsReader);
		multidimensionalOffsetOfVariableLocationInRegister = new int[registerIndices];
		for (int i = 0; i < registerIndices; i++) {
			multidimensionalOffsetOfVariableLocationInRegister[i] = reader.parseInt();
		}
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		builder.append(String.format(": %s, RegisterIndices = %d, ", registerName.toString(),
			registerIndices));
		builder.append(memorySpace);
		emitRangeAndGaps(builder);
		for (int i = 0; i < registerIndices; i++) {
			builder.append(
				String.format(" %d", multidimensionalOffsetOfVariableLocationInRegister[i]));
		}
	}

}
