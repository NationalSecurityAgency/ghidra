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
 * Instruction annotation used for certain PDB symbols for inlined functions.
 * @see InlinedFunctionCallsiteMsSymbol
 * @see InlinedFunctionCallsiteExtendedMsSymbol
 */
public class InstructionAnnotation extends AbstractParsableItem {

	public enum Opcode {

		INVALID("Illegal", 0),
		CODE_OFFSET("Offset", 1),
		CHANGE_CODE_OFFSET_BASE("CodeOffsetBase", 2),
		CHANGE_CODE_OFFSET("CodeOffset", 3),
		CHANGE_CODE_LENGTH("CodeLength", 0x04),
		CHANGE_FILE("File", 0x05),
		CHANGE_LINE_OFFSET("LineOffset", 0x06),
		CHANGE_LINE_END_DELTA("LineEndDelta", 0x07),
		CHANGE_RANGE_KIND("RangeKind", 0x08),
		CHANGE_COLUMN_START("ColumnStart", 0x09),
		CHANGE_COLUMN_END_DELTA("ColumnEndDelta", 0x0a),
		CHANGE_CODE_OFFSET_AND_LINE_OFFSET("CodeOffsetAndLineOffset", 0x0b),
		CHANGE_CODE_LENGTH_AND_CODE_OFFSET("CodeLengthAndCodeOffset", 0x0c),
		CHANGE_COLUMN_END("ColumnEnd", 0x0d);

		private static final Map<Integer, Opcode> BY_VALUE = new HashMap<>();
		static {
			for (Opcode val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String label;
		public final int value;

		@Override
		public String toString() {
			return label;
		}

		public static Opcode fromValue(int val) {
			return BY_VALUE.getOrDefault(val, INVALID);
		}

		private Opcode(String label, int value) {
			this.label = label;
			this.value = value;
		}
	}

	//==============================================================================================
	private Opcode instructionCode;
	private long parameter1;
	private long parameter2;

	//==============================================================================================
	/**
	 * Constructor for this symbol component.
	 * @param reader {@link PdbByteReader} from which this data is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public InstructionAnnotation(PdbByteReader reader) throws PdbException {
		instructionCode = Opcode.fromValue(decompressData(reader));
		if (instructionCode == Opcode.INVALID) {
			reader.align4();
		}
		else if (instructionCode == Opcode.CHANGE_CODE_LENGTH_AND_CODE_OFFSET) {
			parameter1 = decompressData(reader);
			parameter2 = decompressData(reader);
		}
		else if ((instructionCode == Opcode.CHANGE_LINE_OFFSET) ||
			(instructionCode == Opcode.CHANGE_COLUMN_END_DELTA)) {
			parameter1 = decodeSignedInt32(decompressData(reader));
			parameter2 = -1;
		}
		else {
			parameter1 = decompressData(reader);
			parameter2 = -1;
		}
	}

	public Opcode getInstructionCode() {
		return instructionCode;
	}

	@Override
	public void emit(StringBuilder builder) {
		if (instructionCode == Opcode.CHANGE_CODE_LENGTH_AND_CODE_OFFSET) {
			builder.append(
				"  " + instructionCode + String.format(" %x %x", parameter1, parameter2));
		}
		else if (instructionCode == Opcode.CHANGE_CODE_OFFSET_AND_LINE_OFFSET) {
			// CodeDelta is lower 4 bits, SourceDelta rest of the bits.
			builder.append("  " + instructionCode +
				String.format(" %x %x", (parameter1 >> 4) & 0x0fffffff, parameter1 & 0x0f));
		}
		else {
			builder.append("  " + instructionCode + String.format(" %x", (int) parameter1));
		}
	}

	private int decompressData(PdbByteReader reader) throws PdbException {
		int result = Integer.MIN_VALUE;
		int val = reader.parseUnsignedByteVal();
		if (val < 0x80) {
			result = val;
		}
		else if ((val & 0xc0) == 0x80) {
			result = (val & 0x3f) << 8;
			result |= reader.parseUnsignedByteVal();
		}
		else if ((val & 0xe0) == 0xc0) {
			result = (val & 0x1f) << 24;
			result |= reader.parseUnsignedByteVal() << 16;
			result |= reader.parseUnsignedByteVal() << 8;
			result |= reader.parseUnsignedByteVal();
		}
		return result;
	}

	private int decodeSignedInt32(int input) {
		if ((input & 0x01) == 0x01) {
			return -(input >> 1);
		}
		return input >> 1;
	}

}
