/* ###
 * IP: GHIDRA
 * NOTE: This was included for debugging purposes; while it has utility, better and more complete options should be considered...
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
package ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.plugin.exceptionhandlers.gcc.GccAnalysisUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;

/**
 * An opcode parser for operands of a call frame instruction. 
 * The operands are encoded as DWARF expressions.
 * <p>
 * The data encodings can be found in the DWARF Debugging Information Format specification
 * under Call Frame Information in the Data Representation section.
 */
public class DwarfCallFrameOpcodeParser {

	private static final int WHOLE_BYTE_MASK = 0xff;
	private static final int HIGH_2_BITS_MASK = 0xc0;
	private static final int LOW_6_BITS_MASK = 0x3f;

	private static final int DW_CFA_nop = 0x0;

	private static final int DW_CFA_advance_loc = 0x40;
	private static final int DW_CFA_offset = 0x80;
	private static final int DW_CFA_restore = 0xc0;

	private static final int DW_CFA_set_loc = 0x01;
	private static final int DW_CFA_advance_loc1 = 0x02;
	private static final int DW_CFA_advance_loc2 = 0x03;
	private static final int DW_CFA_advance_loc4 = 0x04;
	private static final int DW_CFA_offset_extended = 0x05;
	private static final int DW_CFA_restore_extended = 0x06;
	private static final int DW_CFA_undefined = 0x07;
	private static final int DW_CFA_same_value = 0x08;
	private static final int DW_CFA_register = 0x09;
	private static final int DW_CFA_remember_state = 0x0a;
	private static final int DW_CFA_restore_state = 0x0b;

	private static final int DW_CFA_def_cfa = 0x0c;
	private static final int DW_CFA_def_cfa_register = 0x0d;
	private static final int DW_CFA_def_cfa_offset = 0x0e;
	private static final int DW_CFA_def_cfa_expression = 0x0f;

	private static final int DW_CFA_expression = 0x10;
	private static final int DW_CFA_offset_extended_sf = 0x11;
	private static final int DW_CFA_def_cfa_sf = 0x12;
	private static final int DW_CFA_def_cfa_offset_sf = 0x13;
	private static final int DW_CFA_val_offset = 0x14;
	private static final int DW_CFA_val_offset_sf = 0x15;
	private static final int DW_CFA_val_expression = 0x16;

	private static final int DW_CFA_MIPS_advance_loc8 = 0x1d;
	private static final int DW_CFA_GNU_window_save = 0x2d;
	private static final int DW_CFA_GNU_args_size = 0x2e;
	private static final int DW_CFA_lo_user = 0x1c;
	private static final int DW_CFA_hi_user = 0x3f;

	private Program program;
	private Address address;
	private int length;

	/**
	 * Constructs an opcode parser.
	 * @param program the program with the bytes to parse
	 * @param address the address of the bytes to parse
	 * @param length the number of bytes to parse
	 */
	public DwarfCallFrameOpcodeParser(Program program, Address address, int length) {
		this.program = program;
		this.address = address;
		this.length = length;
	}

	void parse() throws MemoryAccessException {
		Address curr = address;
		Address limit = address.add(length);

		int exOpcodeOrParam;
		long operand1;
		int operand1Len;
		long operand2;
		int operand2Len;

		while (curr.compareTo(limit) < 0) {

			StringBuilder sb = new StringBuilder();
			Address instrAddr = curr;

			int opbyte = GccAnalysisUtils.readByte(program, curr) & WHOLE_BYTE_MASK;

			int opcode = (opbyte & HIGH_2_BITS_MASK);

			exOpcodeOrParam = (opbyte & LOW_6_BITS_MASK);
			boolean primaryOpcode = opcode != 0;

			curr = curr.add(1);

			if (primaryOpcode) {
				switch (opcode) {

					case DW_CFA_advance_loc:
						primaryOpcode = true;

						sb.append("DW_CFA_advance_loc delta[" + exOpcodeOrParam + "]");
						break;
					case DW_CFA_offset:
						primaryOpcode = true;
						operand1 = GccAnalysisUtils.readULEB128(program, curr);
						operand1Len = GccAnalysisUtils.getULEB128Length(program, curr);

						curr = curr.add(operand1Len);

						sb.append("DW_CFA_offset reg[" + exOpcodeOrParam + "] " + operand1);
						break;
					case DW_CFA_restore:
						primaryOpcode = true;
						sb.append("DW_CFA_restore reg[" + exOpcodeOrParam + "]");
						break;
				}
			}
			else {
				switch (exOpcodeOrParam) {

					//  case DW_CFA_extended:
					case DW_CFA_nop:
						primaryOpcode = true;
						sb.append("DW_CFA_nop");
						break;

					case DW_CFA_set_loc:

						// NOTE: This may actually be a LE128-encoded value..
						operand1 = GccAnalysisUtils.readDWord(program, curr) & 0xFFFFFFFF;
						curr = curr.add(4);

						sb.append("DW_CFA_set_loc addr[" + operand1 + "]");
						break;

					case DW_CFA_advance_loc1:
						operand1 = GccAnalysisUtils.readByte(program, curr) & 0xFF;
						curr = curr.add(1);

						sb.append("DW_CFA_advance_loc1 delta[" + operand1 + "]");
						break;

					case DW_CFA_advance_loc2:
						operand1 = GccAnalysisUtils.readWord(program, curr) & 0xFFFF;
						curr = curr.add(2);

						sb.append("DW_CFA_advance_loc2 delta[" + operand1 + "]");
						break;

					case DW_CFA_advance_loc4:
						operand1 = GccAnalysisUtils.readDWord(program, curr) & 0xFFFFFFFF;
						curr = curr.add(4);

						sb.append("DW_CFA_advance_loc4 delta[" + operand1 + "]");
						break;

					case DW_CFA_offset_extended:
						operand1 = GccAnalysisUtils.readULEB128(program, curr);
						operand1Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand1Len);

						operand2 = GccAnalysisUtils.readULEB128(program, curr);
						operand2Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand2Len);

						sb.append(
							"DW_CFA_offset_extended reg[" + operand1 + "] reg[" + operand2 + "]");
						break;

					case DW_CFA_restore_extended:
						operand1 = GccAnalysisUtils.readULEB128(program, curr);
						operand1Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand1Len);

						sb.append("DW_CFA_restore_extended reg[" + operand1 + "]");
						break;

					case DW_CFA_undefined:
						operand1 = GccAnalysisUtils.readULEB128(program, curr);
						operand1Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand1Len);

						sb.append("DW_CFA_undefined reg[" + operand1 + "]");
						break;

					case DW_CFA_same_value:
						operand1 = GccAnalysisUtils.readULEB128(program, curr);
						operand1Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand1Len);

						sb.append("DW_CFA_same_value reg[" + operand1 + "]");
						break;

					case DW_CFA_register:
						operand1 = GccAnalysisUtils.readULEB128(program, curr);
						operand1Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand1Len);

						operand2 = GccAnalysisUtils.readULEB128(program, curr);
						operand2Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand2Len);

						sb.append("DW_CFA_register reg[" + operand1 + "] reg[" + operand2 + "]");
						break;

					case DW_CFA_remember_state:
						sb.append("DW_CFA_remember_state");
						break;

					case DW_CFA_restore_state:
						sb.append("DW_CFA_restore_state");
						break;

					case DW_CFA_def_cfa:
						operand1 = GccAnalysisUtils.readULEB128(program, curr);
						operand1Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand1Len);

						operand2 = GccAnalysisUtils.readULEB128(program, curr);
						operand2Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand2Len);

						sb.append("DW_CFA_def_cfa reg[" + operand1 + "] offs[" + operand2 + "]");
						break;

					case DW_CFA_def_cfa_register:
						operand1 = GccAnalysisUtils.readULEB128(program, curr);
						operand1Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand1Len);

						sb.append("DW_CFA_def_cfa_register reg[" + operand1 + "]");
						break;

					case DW_CFA_def_cfa_offset:
						operand1 = GccAnalysisUtils.readULEB128(program, curr);
						operand1Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand1Len);

						sb.append("DW_CFA_def_cfa_offset offs[" + operand1 + "]");
						break;

					case DW_CFA_def_cfa_expression:
						sb.append("DW_CFA_def_cfa_expression BLOCK");
						break;

					case DW_CFA_expression:

						operand1 = GccAnalysisUtils.readULEB128(program, curr);
						operand1Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand1Len);

						sb.append("DW_CFA_expression reg[" + operand1 + "] BLOCK");
						break;

					case DW_CFA_offset_extended_sf:
						operand1 = GccAnalysisUtils.readULEB128(program, curr);
						operand1Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand1Len);

						operand2 = GccAnalysisUtils.readULEB128(program, curr);
						operand2Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand2Len);

						sb.append("DW_CFA_offset_extended_sf reg[" + operand1 + "] offs[" +
							operand2 + "]");
						break;

					case DW_CFA_def_cfa_sf:
						operand1 = GccAnalysisUtils.readULEB128(program, curr);
						operand1Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand1Len);

						operand2 = GccAnalysisUtils.readULEB128(program, curr);
						operand2Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand2Len);

						sb.append("DW_CFA_def_cfa_sf reg[" + operand1 + "] offs[" + operand2 + "]");
						break;

					case DW_CFA_def_cfa_offset_sf:
						operand1 = GccAnalysisUtils.readULEB128(program, curr);
						operand1Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand1Len);

						sb.append("DW_CFA_def_cfa_offset_sf offs[" + operand1 + "]");
						break;

					case DW_CFA_val_offset:
						operand1 = GccAnalysisUtils.readULEB128(program, curr);
						operand1Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand1Len);

						operand2 = GccAnalysisUtils.readULEB128(program, curr);
						operand2Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand2Len);

						sb.append("DW_CFA_val_offset [" + operand1 + "] [" + operand2 + "]");
						break;

					case DW_CFA_val_offset_sf:
						operand1 = GccAnalysisUtils.readULEB128(program, curr);
						operand1Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand1Len);

						operand2 = GccAnalysisUtils.readULEB128(program, curr);
						operand2Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand2Len);

						sb.append("DW_CFA_val_offset_sf [" + operand1 + "] [" + operand2 + "]");
						break;

					case DW_CFA_val_expression:
						operand1 = GccAnalysisUtils.readULEB128(program, curr);
						operand1Len = GccAnalysisUtils.getULEB128Length(program, curr);
						curr = curr.add(operand1Len);

						sb.append("DW_CFA_val_expression [" + operand1 + "] BLOCK");
						break;

					case DW_CFA_MIPS_advance_loc8:
						operand1 = GccAnalysisUtils.readQWord(program, curr) & 0xFFFF;
						curr = curr.add(8);

						sb.append("DW_CFA_MIPS_advance_loc8 + " + operand1);

						break;

					case DW_CFA_GNU_window_save:
						sb.append("DW_CFA_GNU_window_save");
						break;

					case DW_CFA_GNU_args_size:
						operand1 = GccAnalysisUtils.readByte(program, curr);
						curr = curr.add(1);
						sb.append("DW_CFA_GNU_args_size [" + operand1 + "]");
						break;

					case DW_CFA_lo_user:
						sb.append("DW_CFA_lo_user");
						break;

					case DW_CFA_hi_user:
						sb.append("DW_CFA_hi_user");
						break;

				}
			}

			SetCommentCmd.createComment(program, instrAddr, sb.toString(), CodeUnit.EOL_COMMENT);

			Msg.info(this, sb.toString());
		}
	}

}
