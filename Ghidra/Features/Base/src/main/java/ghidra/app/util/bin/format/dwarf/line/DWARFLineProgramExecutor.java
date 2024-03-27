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
package ghidra.app.util.bin.format.dwarf.line;

import static ghidra.app.util.bin.format.dwarf.line.DWARFLineNumberExtendedOpcodes.*;
import static ghidra.app.util.bin.format.dwarf.line.DWARFLineNumberStandardOpcodes.*;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.LEB128;

/**
 * Handles executing, step-by-step, the address-to-sourcefile mapping instructions found at the
 * end of a DWARFLine structure. 
 */
public final class DWARFLineProgramExecutor implements Closeable {
	private DWARFLineProgramState state;
	private BinaryReader reader;
	private final int pointerSize;
	private final long streamEnd;
	private final int opcodeBase;
	private final int lineRange;
	private final int lineBase;
	private final int minInstrLen;
	private final boolean defaultIsStatement;

	public DWARFLineProgramExecutor(BinaryReader reader, long streamEnd, int pointerSize,
			int opcodeBase, int lineBase, int lineRange, int minInstrLen,
			boolean defaultIsStatement) {
		this.reader = reader;
		this.streamEnd = streamEnd;
		this.pointerSize = pointerSize;
		this.opcodeBase = opcodeBase;
		this.lineBase = lineBase;
		this.lineRange = lineRange;
		this.minInstrLen = minInstrLen;
		this.defaultIsStatement = defaultIsStatement;
	}

	@Override
	public void close() {
		reader = null;
	}

	public boolean hasNext() {
		return reader.getPointerIndex() < streamEnd;
	}

	public DWARFLineProgramState currentState() {
		return new DWARFLineProgramState(state);
	}

	public DWARFLineProgramState nextRow() throws IOException {
		while (hasNext()) {
			DWARFLineProgramInstruction instr = step();
			if (instr.row() != null) {
				return instr.row();
			}
		}
		return null;
	}

	public List<DWARFLineProgramState> allRows() throws IOException {
		List<DWARFLineProgramState> results = new ArrayList<>();

		DWARFLineProgramState row;
		while ((row = nextRow()) != null) {
			results.add(row);
		}
		return results;
	}

	/**
	 * Read the next instruction and executes it
	 * 
	 * @return 
	 * @throws IOException if an i/o error occurs
	 */
	public DWARFLineProgramInstruction step() throws IOException {
		DWARFLineProgramInstruction instr = stepInstr();
		return instr;
	}

	private DWARFLineProgramInstruction stepInstr() throws IOException {
		if (state == null) {
			state = new DWARFLineProgramState(defaultIsStatement);
		}

		long instrOffset = reader.getPointerIndex();

		int opcode = reader.readNextUnsignedByte();

		if (opcode == 0) {
			return executeExtended(instrOffset);
		}
		else if (opcode >= opcodeBase) {
			return executeSpecial(instrOffset, opcode);
		}
		else {
			return executeStandard(instrOffset, opcode);
		}
	}

	private DWARFLineProgramInstruction executeSpecial(long instrOffset, int specialOpcodeValue) {
		int adjustedOpcode = (specialOpcodeValue & 0xff) - opcodeBase;
		int addressIncrement = adjustedOpcode / lineRange;
		int lineIncrement = lineBase + (adjustedOpcode % lineRange);

		addressIncrement &= 0xff;
		lineIncrement &= 0xff;

		state.line += (byte) lineIncrement;
		state.address += (addressIncrement * minInstrLen);

		DWARFLineProgramState row = currentState();

		state.isBasicBlock = false;
		state.prologueEnd = false;
		state.epilogueBegin = false;
		state.discriminator = 0;

		return new DWARFLineProgramInstruction(instrOffset, "DW_LN_special_" + specialOpcodeValue,
			List.of(addressIncrement, lineIncrement), row);
	}

	private DWARFLineProgramInstruction executeExtended(long instrOffset) throws IOException {
		int length = reader.readNextUnsignedVarIntExact(LEB128::unsigned);

		long oldIndex = reader.getPointerIndex();
		int extendedOpcode = reader.readNextByte();

		String instr = DWARFLineNumberExtendedOpcodes.toString(extendedOpcode);
		List<Number> operands = List.of();
		DWARFLineProgramState row = null;

		switch (extendedOpcode) {
			case DW_LNE_end_sequence:
				// end_seq is a special marker, and by definition specifies a row that is one byte
				// after the last instruction of the sequence. 
				state.isEndSequence = true;
				row = currentState();
				row.address--; // tweak backwards 1 byte
				state = new DWARFLineProgramState(defaultIsStatement);
				break;
			case DW_LNE_set_address:
				state.address = reader.readNextUnsignedValue(pointerSize);
				operands = List.of(state.address);
				break;
			case DW_LNE_define_file: {
				// this instruction is deprecated in v5+, and not fully supported in this
				// impl
				String sourceFilename = reader.readNextUtf8String();
				int dirIndex = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
				long lastMod = reader.readNext(LEB128::unsigned);
				long fileLen = reader.readNext(LEB128::unsigned);
				break;
			}
			case DW_LNE_set_discriminator:
				state.discriminator = reader.readNext(LEB128::unsigned);
				operands = List.of(state.discriminator);
				break;
			default:
				throw new DWARFLineException("Unknown extended instruction: " + instr);
		}

		if (oldIndex + length != reader.getPointerIndex()) {
			throw new DWARFLineException("Bad extended opcode decoding, length mismatch @0x%x: %s"
					.formatted(oldIndex, instr));
		}

		return new DWARFLineProgramInstruction(instrOffset, instr, operands, row);
	}

	private DWARFLineProgramInstruction executeStandard(long instrOffset, int opcode)
			throws IOException {

		String instr = DWARFLineNumberStandardOpcodes.toString(opcode);
		List<Number> operands = List.of();
		DWARFLineProgramState row = null;

		switch (opcode) {
			case DW_LNS_copy: {
				row = currentState();

				state.discriminator = 0;
				state.isBasicBlock = false;
				state.prologueEnd = false;
				state.epilogueBegin = false;
				break;
			}
			case DW_LNS_advance_pc: {
				long value = reader.readNext(LEB128::unsigned);
				operands = List.of(value);

				state.address += (value * minInstrLen);
				break;
			}
			case DW_LNS_advance_line: {
				int value = reader.readNextVarInt(LEB128::signed);
				operands = List.of(value);

				state.line += value;
				break;
			}
			case DW_LNS_set_file: {
				int value = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
				operands = List.of(value);

				state.file = value;
				break;
			}
			case DW_LNS_set_column: {
				int value = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
				operands = List.of(value);

				state.column = value;
				break;
			}
			case DW_LNS_negate_statement: {
				state.isStatement = !state.isStatement;
				break;
			}
			case DW_LNS_set_basic_block: {
				state.isBasicBlock = true;
				break;
			}
			case DW_LNS_const_add_pc: {
				int adjustedOpcode = 255 - opcodeBase;
				int addressIncrement = adjustedOpcode / lineRange;
				state.address += (addressIncrement & 0xff);
				break;
			}
			case DW_LNS_fixed_advanced_pc: {
				int value = reader.readNextUnsignedShort();
				operands = List.of(value);

				state.address += value;
				break;
			}

			case DW_LNS_set_prologue_end:
				state.prologueEnd = true;
				break;

			case DW_LNS_set_epilog_begin:
				state.epilogueBegin = true;
				break;

			case DW_LNS_set_isa: {
				long value = reader.readNext(LEB128::unsigned);
				operands = List.of(value);

				state.isa = value;
				break;
			}

			default:
				throw new DWARFLineException("Unsupported standard opcode: " + instr);
		}

		return new DWARFLineProgramInstruction(instrOffset, instr, operands, row);
	}
}
