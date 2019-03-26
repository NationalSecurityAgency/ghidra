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
package ghidra.app.util.bin.format.dwarf4.expression;

import static ghidra.app.util.bin.format.dwarf4.expression.DWARFExpressionOperandType.*;

import java.lang.reflect.Field;
import java.util.*;

import ghidra.app.util.bin.format.dwarf4.DWARFUtil;

/**
 * DWARF expression opcode consts from www.dwarfstd.org/doc/DWARF4.pdf
 */
public class DWARFExpressionOpCodes {
	public static final int DW_OP_addr = 0x3;
	public static final int DW_OP_deref = 0x6;
	public static final int DW_OP_const1u = 0x8;
	public static final int DW_OP_const1s = 0x9;
	public static final int DW_OP_const2u = 0xa;
	public static final int DW_OP_const2s = 0xb;
	public static final int DW_OP_const4u = 0xc;
	public static final int DW_OP_const4s = 0xd;
	public static final int DW_OP_const8u = 0xe;
	public static final int DW_OP_const8s = 0xf;
	public static final int DW_OP_constu = 0x10;
	public static final int DW_OP_consts = 0x11;
	public static final int DW_OP_dup = 0x12;
	public static final int DW_OP_drop = 0x13;
	public static final int DW_OP_over = 0x14;
	public static final int DW_OP_pick = 0x15;
	public static final int DW_OP_swap = 0x16;
	public static final int DW_OP_rot = 0x17;
	public static final int DW_OP_xderef = 0x18;
	public static final int DW_OP_abs = 0x19;
	public static final int DW_OP_and = 0x1a;
	public static final int DW_OP_div = 0x1b;
	public static final int DW_OP_minus = 0x1c;
	public static final int DW_OP_mod = 0x1d;
	public static final int DW_OP_mul = 0x1e;
	public static final int DW_OP_neg = 0x1f;
	public static final int DW_OP_not = 0x20;
	public static final int DW_OP_or = 0x21;
	public static final int DW_OP_plus = 0x22;
	public static final int DW_OP_plus_uconst = 0x23;
	public static final int DW_OP_shl = 0x24;
	public static final int DW_OP_shr = 0x25;
	public static final int DW_OP_shra = 0x26;
	public static final int DW_OP_xor = 0x27;
	public static final int DW_OP_bra = 0x28;
	public static final int DW_OP_eq = 0x29;
	public static final int DW_OP_ge = 0x2a;
	public static final int DW_OP_gt = 0x2b;
	public static final int DW_OP_le = 0x2c;
	public static final int DW_OP_lt = 0x2d;
	public static final int DW_OP_ne = 0x2e;
	public static final int DW_OP_skip = 0x2f;
	public static final int DW_OP_lit0 = 0x30;
	public static final int DW_OP_lit1 = 0x31;
	public static final int DW_OP_lit2 = 0x32;
	public static final int DW_OP_lit3 = 0x33;
	public static final int DW_OP_lit4 = 0x34;
	public static final int DW_OP_lit5 = 0x35;
	public static final int DW_OP_lit6 = 0x36;
	public static final int DW_OP_lit7 = 0x37;
	public static final int DW_OP_lit8 = 0x38;
	public static final int DW_OP_lit9 = 0x39;
	public static final int DW_OP_lit10 = 0x3a;
	public static final int DW_OP_lit11 = 0x3b;
	public static final int DW_OP_lit12 = 0x3c;
	public static final int DW_OP_lit13 = 0x3d;
	public static final int DW_OP_lit14 = 0x3e;
	public static final int DW_OP_lit15 = 0x3f;
	public static final int DW_OP_lit16 = 0x40;
	public static final int DW_OP_lit17 = 0x41;
	public static final int DW_OP_lit18 = 0x42;
	public static final int DW_OP_lit19 = 0x43;
	public static final int DW_OP_lit20 = 0x44;
	public static final int DW_OP_lit21 = 0x45;
	public static final int DW_OP_lit22 = 0x46;
	public static final int DW_OP_lit23 = 0x47;
	public static final int DW_OP_lit24 = 0x48;
	public static final int DW_OP_lit25 = 0x49;
	public static final int DW_OP_lit26 = 0x4a;
	public static final int DW_OP_lit27 = 0x4b;
	public static final int DW_OP_lit28 = 0x4c;
	public static final int DW_OP_lit29 = 0x4d;
	public static final int DW_OP_lit30 = 0x4e;
	public static final int DW_OP_lit31 = 0x4f;
	public static final int DW_OP_reg0 = 0x50;
	public static final int DW_OP_reg1 = 0x51;
	public static final int DW_OP_reg2 = 0x52;
	public static final int DW_OP_reg3 = 0x53;
	public static final int DW_OP_reg4 = 0x54;
	public static final int DW_OP_reg5 = 0x55;
	public static final int DW_OP_reg6 = 0x56;
	public static final int DW_OP_reg7 = 0x57;
	public static final int DW_OP_reg8 = 0x58;
	public static final int DW_OP_reg9 = 0x59;
	public static final int DW_OP_reg10 = 0x5a;
	public static final int DW_OP_reg11 = 0x5b;
	public static final int DW_OP_reg12 = 0x5c;
	public static final int DW_OP_reg13 = 0x5d;
	public static final int DW_OP_reg14 = 0x5e;
	public static final int DW_OP_reg15 = 0x5f;
	public static final int DW_OP_reg16 = 0x60;
	public static final int DW_OP_reg17 = 0x61;
	public static final int DW_OP_reg18 = 0x62;
	public static final int DW_OP_reg19 = 0x63;
	public static final int DW_OP_reg20 = 0x64;
	public static final int DW_OP_reg21 = 0x65;
	public static final int DW_OP_reg22 = 0x66;
	public static final int DW_OP_reg23 = 0x67;
	public static final int DW_OP_reg24 = 0x68;
	public static final int DW_OP_reg25 = 0x69;
	public static final int DW_OP_reg26 = 0x6a;
	public static final int DW_OP_reg27 = 0x6b;
	public static final int DW_OP_reg28 = 0x6c;
	public static final int DW_OP_reg29 = 0x6d;
	public static final int DW_OP_reg30 = 0x6e;
	public static final int DW_OP_reg31 = 0x6f;
	public static final int DW_OP_breg0 = 0x70;
	public static final int DW_OP_breg1 = 0x71;
	public static final int DW_OP_breg2 = 0x72;
	public static final int DW_OP_breg3 = 0x73;
	public static final int DW_OP_breg4 = 0x74;
	public static final int DW_OP_breg5 = 0x75;
	public static final int DW_OP_breg6 = 0x76;
	public static final int DW_OP_breg7 = 0x77;
	public static final int DW_OP_breg8 = 0x78;
	public static final int DW_OP_breg9 = 0x79;
	public static final int DW_OP_breg10 = 0x7a;
	public static final int DW_OP_breg11 = 0x7b;
	public static final int DW_OP_breg12 = 0x7c;
	public static final int DW_OP_breg13 = 0x7d;
	public static final int DW_OP_breg14 = 0x7e;
	public static final int DW_OP_breg15 = 0x7f;
	public static final int DW_OP_breg16 = 0x80;
	public static final int DW_OP_breg17 = 0x81;
	public static final int DW_OP_breg18 = 0x82;
	public static final int DW_OP_breg19 = 0x83;
	public static final int DW_OP_breg20 = 0x84;
	public static final int DW_OP_breg21 = 0x85;
	public static final int DW_OP_breg22 = 0x86;
	public static final int DW_OP_breg23 = 0x87;
	public static final int DW_OP_breg24 = 0x88;
	public static final int DW_OP_breg25 = 0x89;
	public static final int DW_OP_breg26 = 0x8a;
	public static final int DW_OP_breg27 = 0x8b;
	public static final int DW_OP_breg28 = 0x8c;
	public static final int DW_OP_breg29 = 0x8d;
	public static final int DW_OP_breg30 = 0x8e;
	public static final int DW_OP_breg31 = 0x8f;
	public static final int DW_OP_regx = 0x90;
	public static final int DW_OP_fbreg = 0x91;
	public static final int DW_OP_bregx = 0x92;
	public static final int DW_OP_piece = 0x93;
	public static final int DW_OP_deref_size = 0x94;
	public static final int DW_OP_xderef_size = 0x95;
	public static final int DW_OP_nop = 0x96;
	public static final int DW_OP_push_object_address = 0x97;
	public static final int DW_OP_call2 = 0x98;
	public static final int DW_OP_call4 = 0x99;
	public static final int DW_OP_call_ref = 0x9a;
	public static final int DW_OP_form_tls_address = 0x9b;
	public static final int DW_OP_call_frame_cfa = 0x9c;
	public static final int DW_OP_bit_piece = 0x9d;
	public static final int DW_OP_implicit_value = 0x9e;
	public static final int DW_OP_stack_value = 0x9f;
	public static final int DW_OP_lo_user = 0xe0;
	public static final int DW_OP_hi_user = 0xff;

	public static boolean isValidOpcode(int opcode) {
		Field field = DWARFUtil.getStaticFinalFieldWithValue(DWARFExpressionOpCodes.class, opcode);
		return field != null && field.getName().startsWith("DW_OP_");
	}

	/**
	 * These opcodes are known, but can not be evaluated in the current Ghidra DWARF code
	 */
	public static final int[] UNSUPPORTED_OPCODES_LIST = { DW_OP_deref_size, DW_OP_xderef,
		DW_OP_xderef_size, DW_OP_push_object_address, DW_OP_form_tls_address, DW_OP_call2,
		DW_OP_call4, DW_OP_call_ref, DW_OP_implicit_value };

	/**
	 * These opcodes are known, but can not be evaluated in the current Ghidra DWARF code.
	 */
	public static final Set<Integer> UNSUPPORTED_OPCODES = new HashSet<>();

	static {
		for (int opcode : UNSUPPORTED_OPCODES) {
			UNSUPPORTED_OPCODES.add(opcode);
		}
	}

	/**
	 * Map of opcode to its expected operand types.  If the opcode isn't found in this map,
	 * it is assumed to not take any operands.
	 * Even if Ghidra can't evaluate a DWARF opCode, we should still keep it in this
	 * map so we can parse the expression and display it as a string.
	 */
	static final Map<Integer, DWARFExpressionOperandType[]> OPtoOperandTypes = new HashMap<>();

	static {
		addOperandTypeMapping(DW_OP_addr, ADDR);
		addOperandTypeMapping(DW_OP_const1u, U_BYTE);
		addOperandTypeMapping(DW_OP_const1s, S_BYTE);
		addOperandTypeMapping(DW_OP_const2u, U_SHORT);
		addOperandTypeMapping(DW_OP_const2s, S_SHORT);
		addOperandTypeMapping(DW_OP_const4u, U_INT);
		addOperandTypeMapping(DW_OP_const4s, S_INT);
		addOperandTypeMapping(DW_OP_const8u, U_LONG);
		addOperandTypeMapping(DW_OP_const8s, S_LONG);
		addOperandTypeMapping(DW_OP_constu, U_LEB128);
		addOperandTypeMapping(DW_OP_consts, S_LEB128);
		addOperandTypeMapping(DW_OP_pick, U_BYTE);
		addOperandTypeMapping(DW_OP_plus_uconst, U_LEB128);
		addOperandTypeMapping(DW_OP_skip, S_SHORT);
		addOperandTypeMapping(DW_OP_bra, S_SHORT);
		addOperandTypeMapping(DW_OP_breg0, DW_OP_breg31, S_LEB128);
		addOperandTypeMapping(DW_OP_regx, U_LEB128);
		addOperandTypeMapping(DW_OP_fbreg, S_LEB128);
		addOperandTypeMapping(DW_OP_bregx, U_LEB128, S_LEB128);
		addOperandTypeMapping(DW_OP_piece, U_LEB128);
		addOperandTypeMapping(DW_OP_deref_size, U_BYTE);
		addOperandTypeMapping(DW_OP_xderef_size, U_BYTE);
		addOperandTypeMapping(DW_OP_call2, U_SHORT);
		addOperandTypeMapping(DW_OP_call4, U_INT);
		addOperandTypeMapping(DW_OP_call_ref, DWARF_INT);// U_INT OR U_LONG depending on DWARF32 or DWARF64
		addOperandTypeMapping(DW_OP_bit_piece, U_LEB128, U_LEB128);
		addOperandTypeMapping(DW_OP_implicit_value, U_LEB128, SIZED_BLOB);
	}

	public static final DWARFExpressionOperandType[] EMPTY_OPERANDTYPES = {};
	public static final DWARFExpressionOperandType[] BLOBONLY_OPERANDTYPES =
		{ DWARFExpressionOperandType.SIZED_BLOB };

	private static void addOperandTypeMapping(int opcode,
			DWARFExpressionOperandType... operandTypes) {
		OPtoOperandTypes.put(opcode, operandTypes);
	}

	private static void addOperandTypeMapping(int opcodeLow, int opcodeHigh,
			DWARFExpressionOperandType... operandTypes) {
		for (int i = opcodeLow; i <= opcodeHigh; i++) {
			OPtoOperandTypes.put(i, operandTypes);
		}
	}

	public static DWARFExpressionOperandType[] getOperandTypesFor(int opcode) {
		DWARFExpressionOperandType[] results = OPtoOperandTypes.get(opcode);
		return results != null ? results : EMPTY_OPERANDTYPES;
	}

	public static String toString(int opcode) {
		return DWARFUtil.toString(DWARFExpressionOpCodes.class, opcode);
	}
}
