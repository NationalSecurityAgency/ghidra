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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;

import java.io.IOException;

public final class StatementProgramInstructions {

	//Standard Opcodes

	public final static int DW_LNS_copy = 1;
	public final static int DW_LNS_advance_pc = 2;
	public final static int DW_LNS_advance_line = 3;
	public final static int DW_LNS_set_file = 4;
	public final static int DW_LNS_set_column = 5;
	public final static int DW_LNS_negate_statement = 6;
	public final static int DW_LNS_set_basic_block = 7;
	public final static int DW_LNS_const_add_pc = 8;
	public final static int DW_LNS_fixed_advanced_pc = 9;

	public final static int DW_LNS_set_prologue_end = 10;
	public final static int DW_LNS_set_epilog_begin = 11;
	public final static int DW_LNS_set_isa = 12;

	//Extended Opcodes

	public final static int DW_LNE_end_sequence = 1;
	public final static int DW_LNE_set_address = 2;
	public final static int DW_LNE_define_file = 3;

	private BinaryReader reader;
	private StateMachine machine;
	private StatementProgramPrologue prologue;

	public StatementProgramInstructions(BinaryReader reader, StateMachine machine,
			StatementProgramPrologue prologue) {
		this.reader = reader;
		this.machine = machine;
		this.prologue = prologue;
	}

	public void dispose() {
		reader = null;
		machine = null;
		prologue = null;
	}

	/**
	 * Read the next instruction and executes it 
	 * on the given state machine.
	 * @throws IOException if an i/o error occurs
	 */
	public void execute() throws IOException {
		int opcode = reader.readNextByte() & 0xff;
		if (opcode == 0) {
			executeExtended(opcode);
		}
		else if (opcode >= prologue.getOpcodeBase()) {
			executeSpecial(opcode);
		}
		else {
			executeStandard(opcode);
		}
	}

	private void executeSpecial(int specialOpcodeValue) {
		int adjustedOpcode = (specialOpcodeValue & 0xff) - prologue.getOpcodeBase();
		int addressIncrement = adjustedOpcode / prologue.getLineRange();
		int lineIncrement = prologue.getLineBase() + (adjustedOpcode % prologue.getLineRange());

		addressIncrement &= 0xff;
		lineIncrement &= 0xff;

		machine.line += (byte) lineIncrement;
		machine.address += (addressIncrement * prologue.getMinimumInstructionLength());
		machine.isBasicBlock = false;
	}

	private void executeExtended(int opcode) throws IOException {
		long length = LEB128.readAsLong(reader, false);

		long oldIndex = reader.getPointerIndex();
		int extendedOpcode = reader.readNextByte();

		switch (extendedOpcode) {
			case DW_LNE_end_sequence:
				machine.isEndSequence = true;
				machine.reset(prologue.isDefaultIsStatement());
				break;
			case DW_LNE_set_address:
				machine.address = reader.readNextInt();
				break;
			case DW_LNE_define_file://TODO
				//break;
				throw new UnsupportedOperationException();
		}

		if (oldIndex + length != reader.getPointerIndex()) {
			throw new IllegalStateException("Index values do not match!");
		}
	}

	private void executeStandard(int opcode) throws IOException {
		switch (opcode) {
			case DW_LNS_copy: {
				machine.isBasicBlock = false;
				break;
			}
			case DW_LNS_advance_pc: {
				long value = LEB128.readAsLong(reader, false);
				machine.address += (value * prologue.getMinimumInstructionLength());
				break;
			}
			case DW_LNS_advance_line: {
				long value = LEB128.readAsLong(reader, false);
				machine.line += value;
				break;
			}
			case DW_LNS_set_file: {
				long value = LEB128.readAsLong(reader, false);
				machine.file = (int) value;
				break;
			}
			case DW_LNS_set_column: {
				long value = LEB128.readAsLong(reader, false);
				machine.column = (int) value;
				break;
			}
			case DW_LNS_negate_statement: {
				machine.isStatement = !machine.isStatement;
				break;
			}
			case DW_LNS_set_basic_block: {
				machine.isBasicBlock = true;
				break;
			}
			case DW_LNS_const_add_pc: {
				int adjustedOpcode = 255 - prologue.getOpcodeBase();
				int addressIncrement = adjustedOpcode / prologue.getLineRange();
				machine.address += (addressIncrement & 0xff);
				break;
			}
			case DW_LNS_fixed_advanced_pc: {
				short value = reader.readNextShort();
				machine.address += value;
				break;
			}
		}
	}
}
