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
package ghidra.app.util.bin.format.dwarf.expression;

import static ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionOperandType.*;

import java.util.Arrays;

import ghidra.app.util.bin.format.dwarf.DWARFRegisterMappings;
import ghidra.program.model.lang.Register;

/**
 * DWARF expression opcodes, and their expected operands.
 */
public enum DWARFExpressionOpCode {
	DW_OP_unknown_opcode(0),	// special value, not a real DWARF opcode
	DW_OP_addr(0x3, ADDR),
	DW_OP_deref(0x6),
	DW_OP_const1u(0x8, U_BYTE),
	DW_OP_const1s(0x9, S_BYTE),
	DW_OP_const2u(0xa, U_SHORT),
	DW_OP_const2s(0xb, S_SHORT),
	DW_OP_const4u(0xc, U_INT),
	DW_OP_const4s(0xd, S_INT),
	DW_OP_const8u(0xe, U_LONG),
	DW_OP_const8s(0xf, S_LONG),
	DW_OP_constu(0x10, U_LEB128),
	DW_OP_consts(0x11, S_LEB128),
	DW_OP_dup(0x12),
	DW_OP_drop(0x13),
	DW_OP_over(0x14),
	DW_OP_pick(0x15, U_BYTE),
	DW_OP_swap(0x16),
	DW_OP_rot(0x17),
	DW_OP_xderef(0x18),
	DW_OP_abs(0x19),
	DW_OP_and(0x1a),
	DW_OP_div(0x1b),
	DW_OP_minus(0x1c),
	DW_OP_mod(0x1d),
	DW_OP_mul(0x1e),
	DW_OP_neg(0x1f),
	DW_OP_not(0x20),
	DW_OP_or(0x21),
	DW_OP_plus(0x22),
	DW_OP_plus_uconst(0x23, U_LEB128),
	DW_OP_shl(0x24),
	DW_OP_shr(0x25),
	DW_OP_shra(0x26),
	DW_OP_xor(0x27),
	DW_OP_bra(0x28, S_SHORT),
	DW_OP_eq(0x29),
	DW_OP_ge(0x2a),
	DW_OP_gt(0x2b),
	DW_OP_le(0x2c),
	DW_OP_lt(0x2d),
	DW_OP_ne(0x2e),
	DW_OP_skip(0x2f, S_SHORT),
	DW_OP_lit0(0x30),
	DW_OP_lit1(0x31),
	DW_OP_lit2(0x32),
	DW_OP_lit3(0x33),
	DW_OP_lit4(0x34),
	DW_OP_lit5(0x35),
	DW_OP_lit6(0x36),
	DW_OP_lit7(0x37),
	DW_OP_lit8(0x38),
	DW_OP_lit9(0x39),
	DW_OP_lit10(0x3a),
	DW_OP_lit11(0x3b),
	DW_OP_lit12(0x3c),
	DW_OP_lit13(0x3d),
	DW_OP_lit14(0x3e),
	DW_OP_lit15(0x3f),
	DW_OP_lit16(0x40),
	DW_OP_lit17(0x41),
	DW_OP_lit18(0x42),
	DW_OP_lit19(0x43),
	DW_OP_lit20(0x44),
	DW_OP_lit21(0x45),
	DW_OP_lit22(0x46),
	DW_OP_lit23(0x47),
	DW_OP_lit24(0x48),
	DW_OP_lit25(0x49),
	DW_OP_lit26(0x4a),
	DW_OP_lit27(0x4b),
	DW_OP_lit28(0x4c),
	DW_OP_lit29(0x4d),
	DW_OP_lit30(0x4e),
	DW_OP_lit31(0x4f),
	DW_OP_reg0(0x50),
	DW_OP_reg1(0x51),
	DW_OP_reg2(0x52),
	DW_OP_reg3(0x53),
	DW_OP_reg4(0x54),
	DW_OP_reg5(0x55),
	DW_OP_reg6(0x56),
	DW_OP_reg7(0x57),
	DW_OP_reg8(0x58),
	DW_OP_reg9(0x59),
	DW_OP_reg10(0x5a),
	DW_OP_reg11(0x5b),
	DW_OP_reg12(0x5c),
	DW_OP_reg13(0x5d),
	DW_OP_reg14(0x5e),
	DW_OP_reg15(0x5f),
	DW_OP_reg16(0x60),
	DW_OP_reg17(0x61),
	DW_OP_reg18(0x62),
	DW_OP_reg19(0x63),
	DW_OP_reg20(0x64),
	DW_OP_reg21(0x65),
	DW_OP_reg22(0x66),
	DW_OP_reg23(0x67),
	DW_OP_reg24(0x68),
	DW_OP_reg25(0x69),
	DW_OP_reg26(0x6a),
	DW_OP_reg27(0x6b),
	DW_OP_reg28(0x6c),
	DW_OP_reg29(0x6d),
	DW_OP_reg30(0x6e),
	DW_OP_reg31(0x6f),
	DW_OP_breg0(0x70, S_LEB128),
	DW_OP_breg1(0x71, S_LEB128),
	DW_OP_breg2(0x72, S_LEB128),
	DW_OP_breg3(0x73, S_LEB128),
	DW_OP_breg4(0x74, S_LEB128),
	DW_OP_breg5(0x75, S_LEB128),
	DW_OP_breg6(0x76, S_LEB128),
	DW_OP_breg7(0x77, S_LEB128),
	DW_OP_breg8(0x78, S_LEB128),
	DW_OP_breg9(0x79, S_LEB128),
	DW_OP_breg10(0x7a, S_LEB128),
	DW_OP_breg11(0x7b, S_LEB128),
	DW_OP_breg12(0x7c, S_LEB128),
	DW_OP_breg13(0x7d, S_LEB128),
	DW_OP_breg14(0x7e, S_LEB128),
	DW_OP_breg15(0x7f, S_LEB128),
	DW_OP_breg16(0x80, S_LEB128),
	DW_OP_breg17(0x81, S_LEB128),
	DW_OP_breg18(0x82, S_LEB128),
	DW_OP_breg19(0x83, S_LEB128),
	DW_OP_breg20(0x84, S_LEB128),
	DW_OP_breg21(0x85, S_LEB128),
	DW_OP_breg22(0x86, S_LEB128),
	DW_OP_breg23(0x87, S_LEB128),
	DW_OP_breg24(0x88, S_LEB128),
	DW_OP_breg25(0x89, S_LEB128),
	DW_OP_breg26(0x8a, S_LEB128),
	DW_OP_breg27(0x8b, S_LEB128),
	DW_OP_breg28(0x8c, S_LEB128),
	DW_OP_breg29(0x8d, S_LEB128),
	DW_OP_breg30(0x8e, S_LEB128),
	DW_OP_breg31(0x8f, S_LEB128),
	DW_OP_regx(0x90, U_LEB128),
	DW_OP_fbreg(0x91, S_LEB128),
	DW_OP_bregx(0x92, U_LEB128, S_LEB128),
	DW_OP_piece(0x93, U_LEB128),
	DW_OP_deref_size(0x94, U_BYTE),
	DW_OP_xderef_size(0x95, U_BYTE),
	DW_OP_nop(0x96),
	DW_OP_push_object_address(0x97),
	DW_OP_call2(0x98, U_SHORT),
	DW_OP_call4(0x99, U_INT),
	DW_OP_call_ref(0x9a, DWARF_INT),
	DW_OP_form_tls_address(0x9b),
	DW_OP_call_frame_cfa(0x9c),
	DW_OP_bit_piece(0x9d, U_LEB128, U_LEB128),
	DW_OP_implicit_value(0x9e, U_LEB128, SIZED_BLOB),
	DW_OP_stack_value(0x9f),

	// DWARF5
	DW_OP_implicit_pointer(0xa0, DWARF_INT, S_LEB128),
	DW_OP_addrx(0xa1, U_LEB128),
	DW_OP_constx(0xa2, U_LEB128),
	DW_OP_entry_value(0xa3, U_LEB128, SIZED_BLOB),
	DW_OP_const_type(0xa4, U_LEB128, U_BYTE, SIZED_BLOB),
	DW_OP_regval_type(0xa5, U_LEB128, U_LEB128),
	DW_OP_deref_type(0xa6, U_BYTE, U_LEB128),
	DW_OP_xderef_type(0xa7, U_BYTE, U_LEB128),
	DW_OP_convert(0xa8, U_LEB128),
	DW_OP_reinterpret(0xa9, U_LEB128);

	private static final int DW_OP_lo_user = 0xe0;
	private static final int DW_OP_hi_user = 0xff;

	private final int opcode;
	private final DWARFExpressionOperandType[] operandTypes;

	DWARFExpressionOpCode(int opcode) {
		this.opcode = opcode;
		this.operandTypes = DWARFExpressionOperandType.EMPTY_TYPELIST;
	}

	DWARFExpressionOpCode(int opcode, DWARFExpressionOperandType... operandTypes) {
		this.opcode = opcode;
		this.operandTypes = operandTypes;
	}

	/**
	 * {@return this opcode's raw numeric value}
	 */
	public byte getOpCodeValue() {
		return (byte) opcode;
	}

	/**
	 * {@return the expected operand types that an instruction would have for this opcode}
	 */
	public DWARFExpressionOperandType[] getOperandTypes() {
		return operandTypes;
	}

	private static DWARFExpressionOpCode[] lookupvals = values();
	private static int[] opcodes = getAllOpcodes();

	private static int[] getAllOpcodes() {
		int[] results = new int[lookupvals.length];
		for (int i = 0; i < results.length; i++) {
			results[i] = lookupvals[i].opcode;
		}
		return results;
	}

	/**
	 * {@return true if the specified opcode is in the range (inclusive) of the lo..hi opcodes}
	 * @param op opcode to test
	 * @param lo lowest opcode
	 * @param hi highest opcode
	 */
	public static boolean isInRange(DWARFExpressionOpCode op, DWARFExpressionOpCode lo,
			DWARFExpressionOpCode hi) {
		return lo.opcode <= op.opcode && op.opcode <= hi.opcode;
	}

	/**
	 * Calculates the relative opcode number of this opcode, as compared to a base opcode.
	 * <p>
	 * Example: if this opcode was DW_OP_reg12 (0x5c), and the base op code was DW_OP_reg0 (0x50),
	 * the result value would be 12.
	 * 
	 * @param baseOp base opcode that this opcode is being compared to
	 * @return numeric difference between this opcode and the base opcode
	 */
	public int getRelativeOpCodeOffset(DWARFExpressionOpCode baseOp) {
		return opcode - baseOp.opcode;
	}

	public String toString(DWARFRegisterMappings regMapping) {
		int regIdx = -1;
		if (isInRange(this, DW_OP_reg0, DW_OP_reg31)) {
			regIdx = getRelativeOpCodeOffset(DW_OP_reg0);
		}
		else if (isInRange(this, DW_OP_breg0, DW_OP_breg31)) {
			regIdx = getRelativeOpCodeOffset(DW_OP_breg0);
		}
		Register reg = regIdx >= 0 && regMapping != null ? regMapping.getGhidraReg(regIdx) : null;
		return this.toString() + (reg != null ? "(" + reg.getName() + ")" : "");
	}

	/**
	 * {@return the matching {@link DWARFExpressionOpCode} enum member, or null if unknown opcode}
	 * 
	 * @param opcode numeric value of opcode (currently defined by DWARF as uint8)
	 */
	public static DWARFExpressionOpCode parse(int opcode) {
		// NOTE: the order of this enum's opcode values must be defined in ascending order for this
		// binarysearch to function
		int opcodeIdx = Arrays.binarySearch(opcodes, opcode);
		return opcodeIdx >= 0 ? lookupvals[opcodeIdx] : null;
	}
}
