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
package ghidra.app.util.bin.format.dwarf.macro;

import static ghidra.app.util.bin.format.dwarf.attribs.DWARFForm.*;

import java.util.*;

import ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeDef;
import ghidra.app.util.bin.format.dwarf.attribs.DWARFForm;

/**
 * DWARF macro entry opcodes and their expected operand types.
 * <p>
 * DWARF5
 */
public enum DWARFMacroOpcode {

	/** This is not an official opcode in the DWARF standard, but represents the
	 *  entry with opcode 0 that terminates a macro unit.
	 */
	MACRO_UNIT_TERMINATOR(0, "unknown"),

	DW_MACRO_define(0x1, "#define", DW_FORM_udata, DW_FORM_string),
	DW_MACRO_undef(0x2, "#undef", DW_FORM_udata, DW_FORM_string),
	DW_MACRO_start_file(0x3, "startfile", DW_FORM_udata, DW_FORM_udata),
	DW_MACRO_end_file(0x4, "endfile"),
	DW_MACRO_define_strp(0x5, "#define", DW_FORM_udata, DW_FORM_strp),
	DW_MACRO_undef_strp(0x6, "#undef", DW_FORM_udata, DW_FORM_strp),
	DW_MACRO_import(0x7, "#include", DW_FORM_sec_offset),
	DW_MACRO_define_sup(0x8, "#define", DW_FORM_udata, DW_FORM_strp_sup),
	DW_MACRO_undef_sup(0x9, "#undef", DW_FORM_udata, DW_FORM_strp_sup),
	DW_MACRO_import_sup(0xa, "#include", DW_FORM_sec_offset),
	DW_MACRO_define_strx(0xb, "#define", DW_FORM_udata, DW_FORM_strx),
	DW_MACRO_undef_strx(0xc, "#undef", DW_FORM_udata, DW_FORM_strx);
	//DW_MACRO_lo_user(0xe0),
	//DW_MACRO_hi_user(0xff);

	private final int rawOpcode;
	private final String description;
	private final DWARFForm[] operandForms;

	// enum is small enough that linear search is probably fast enough
	private static DWARFMacroOpcode[] lookupValues = values();

	DWARFMacroOpcode(int rawOpcode, String description, DWARFForm... operandForms) {
		this.rawOpcode = rawOpcode;
		this.description = description;
		this.operandForms = operandForms;
	}

	public int getRawOpcode() {
		return rawOpcode;
	}

	public String getDescription() {
		return description;
	}

	public DWARFForm[] getOperandForms() {
		return operandForms;
	}

	public static DWARFMacroOpcode of(int opcodeVal) {
		for (DWARFMacroOpcode opcode : lookupValues) {
			if (opcode.rawOpcode == opcodeVal) {
				return opcode;
			}
		}
		return null;
	}

	public static final Map<Integer, List<DWARFForm>> defaultOpcodeOperandMap =
		getDefaultOpcodeOperandMap();

	private static Map<Integer, List<DWARFForm>> getDefaultOpcodeOperandMap() {
		Map<Integer, List<DWARFForm>> results = new HashMap<>();
		for (DWARFMacroOpcode opcode : DWARFMacroOpcode.values()) {
			results.put(opcode.getRawOpcode(), List.of(opcode.getOperandForms()));
		}

		return Collections.unmodifiableMap(results);
	}

	public static class Def extends DWARFAttributeDef<DWARFMacroOpcode> {

		public Def(DWARFMacroOpcode opcode, int rawOpcode, DWARFForm form) {
			super(opcode, rawOpcode, form, -1 /* NA */);
		}
	}

}
