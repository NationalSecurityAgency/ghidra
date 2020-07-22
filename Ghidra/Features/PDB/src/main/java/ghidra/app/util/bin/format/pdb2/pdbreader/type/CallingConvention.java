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
package ghidra.app.util.bin.format.pdb2.pdbreader.type;

import java.util.HashMap;
import java.util.Map;

/**
 * Calling Convention used by certain data types.
 * @see AbstractMemberFunctionMsType
 * @see AbstractProcedureMsType
 */
public enum CallingConvention {

	UNKNOWN("INVALID", -1, "INVALID"),
	NEAR_C("__cdecl", 0x00, "near right to left push, caller pops stack"),
	FAR_C("__cdecl", 0x01, "far right to left push, caller pops stack"),
	NEAR_PASCAL("__pascal", 0x02, "near left to right push, callee pops stack"),
	FAR_PASCAL("__pascal", 0x03, "far left to right push, callee pops stack"),
	NEAR_FAST("__fastcall", 0x04, "near left to right push with regs, callee pops stack"),
	FAR_FAST("__fastcall", 0x05, "far left to right push with regs, callee pops stack"),
	SKIPPED("", 0x06, "skipped (unused) call index"),
	NEAR_STD("__stdcall", 0x07, "near standard call"),
	FAR_STD("__stdcall", 0x08, "far standard call"),
	NEAR_SYS("__syscall", 0x09, "near sys call"),
	FAR_SYS("__syscall", 0x0a, "far sys call"),
	THISCALL("__thiscall", 0x0b, "this call (this passed in register)"),
	MIPSCALL("", 0x0c, "Mips call"),
	GENERIC("", 0x0d, "Generic call sequence"),
	ALPHACALL("", 0x0e, "Alpha call"),
	PPCCALL("", 0x0f, "PPC call"),
	SHCALL("", 0x10, "Hitachi SuperH call"),
	ARMCALL("", 0x11, "ARM call"),
	AM33CALL("", 0x12, "AM33 call"),
	TRICALL("", 0x13, "TriCore Call"),
	SH5CALL("", 0x14, "Hitachi SuperH-5 call"),
	M32RCALL("", 0x15, "M32R Call"),
	CLRCALL("", 0x16, "clr call"),
	INLINE("", 0x17, "Marker for routines always inlined and thus lacking a convention"),
	NEAR_VECTOR("__vectorcall", 0x18, "near left to right push with regs, callee pops stack"),
	RESERVED("", 0x19, "first unused call enumeration");

	private static final Map<Integer, CallingConvention> BY_VALUE = new HashMap<>();
	static {
		for (CallingConvention val : values()) {
			BY_VALUE.put(val.value, val);
		}
	}

	private final String label;
	private final int value;
	private final String info;

	@Override
	public String toString() {
		return label;
	}

	public int getValue() {
		return value;
	}

	public String getInfo() {
		return info;
	}

	public static CallingConvention fromValue(int val) {
		return BY_VALUE.getOrDefault(val, UNKNOWN);
	}

	private CallingConvention(String label, int value, String info) {
		this.label = label;
		this.value = value;
		this.info = info;
	}

}
