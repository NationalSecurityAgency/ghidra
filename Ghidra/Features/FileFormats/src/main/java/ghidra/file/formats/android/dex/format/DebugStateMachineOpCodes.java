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
package ghidra.file.formats.android.dex.format;

public final class DebugStateMachineOpCodes {

	/**
	 * <pre>
	 * Terminates a debug info sequence for a code_item
	 * </pre>
	 */
	public final static byte DBG_END_SEQUENCE = 0x00;
	/**
	 * <pre>
	 * Advances the address register without emitting a positions entry
	 * 
	 * addr_diff: amount to add to address register
	 * 
	 * uleb128 addr_diff
	 * </pre>
	 */
	public final static byte DBG_ADVANCE_PC = 0x01;
	/**
	 * <pre>
	 * Advances the line register without emitting a positions entry
	 * 
	 * line_diff: amount to change line register by
	 * 
	 * sleb128 line_diff
	 * </pre>
	 */
	public final static byte DBG_ADVANCE_LINE = 0x02;
	/**
	 * <pre>
	 * Introduces a local variable at the current address. Either name_idx or type_idx may be NO_INDEX to indicate that that value is unknown. 
	 * 
	 * uleb128 register_num
	 * uleb128p1 name_idx
	 * uleb128p1 type_idx
	 * 
	 * register_num: register that will contain local
	 * 	name_idx: string index of the name
	 * 	type_idx: type index of the type
	 * </pre>
	 */
	public final static byte DBG_START_LOCAL = 0x03;
	/**
	 * <pre>
	 * Introduces a local with a type signature at the current address. 
	 * Any of name_idx, type_idx, or sig_idx may be NO_INDEX to indicate that that value is unknown. 
	 * (If sig_idx is -1, though, the same data could be represented more efficiently using the opcode DBG_START_LOCAL.)
	 * 
	 * Note: See the discussion under "dalvik.annotation.Signature" below for caveats about handling signatures.
	 * 
	 * register_num: register that will contain local
	 * 	name_idx: string index of the name
	 * 	type_idx: type index of the type	
	 * 	sig_idx: string index of the type signature
	 * 
	 *  uleb128 register_num
	 *  uleb128p1 name_idx
	 *  uleb128p1 type_idx
	 *  uleb128p1 sig_idx
	 * </pre>
	 */
	public final static byte DBG_START_LOCAL_EXTENDED = 0x04;
	/**
	 * <pre>
	 * Marks a currently-live local variable as out of scope at the current address 
	 * 
	 * register_num: register that contained local
	 * 
	 * uleb128 register_num
	 */
	public final static byte DBG_END_LOCAL = 0x05;
	/**
	 * <pre>
	 * Re-introduces a local variable at the current address. The name and type are the same as the last local that was live in the specified register. 
	 * 
	 * register_num: register to restart
	 * 
	 * uleb128 register_num
	 * 
	 * </pre>
	 */
	public final static byte DBG_RESTART_LOCAL = 0x06;
	/**
	 * <pre>
	 * Sets the prologue_end state machine register, indicating that the next position 
	 * entry that is added should be considered the end of a method prologue 
	 * (an appropriate place for a method breakpoint).
	 * The prologue_end register is cleared by any special (>= 0x0a) opcode.
	 * </pre>
	 */
	public final static byte DBG_SET_PROLOGUE_END = 0x07;
	/**
	 * <pre>
	 * Sets the epilogue_begin state machine register, indicating that 
	 * the next position entry that is added should be considered the 
	 * beginning of a method epilogue (an appropriate place to suspend 
	 * execution before method exit). 
	 * The epilogue_begin register is cleared by any special (>= 0x0a) opcode.
	 * </pre>
	 */
	public final static byte DBG_SET_EPILOGUE_BEGIN = 0x08;
	/**
	 * <pre>
	 * Indicates that all subsequent line number entries make reference to this source file name, instead of the default name specified in code_item 
	 * 
	 * name_idx: string index of source file name; NO_INDEX if unknown 
	 * 
	 * uleb128p1 name_idx
	 * </pre>
	 */
	public final static byte DBG_SET_FILE = 0x09;

	/**
	 * <pre>
	 * Advances the line and address registers, emits a position entry, and clears prologue_end and epilogue_begin. See below for description.
	 * 
	 * Special Opcodes 0x0a...0xff (none) advances the line and address registers, emits a position entry, and clears prologue_end and epilogue_begin. See below for description.
	 * </pre>
	 */
	public final static boolean isSpecialOpCode(byte opcode) {
		return (opcode & 0xff) >= 0xa && (opcode & 0xff) <= 0xff;
	}

}
