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
package ghidra.app.util.bin.format.macho.commands.dyld;

import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.program.model.data.*;

/**
 * Bind opcodes
 * 
 * @see <a href="https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h">EXTERNAL_HEADERS/mach-o/loader.h</a> 
 */
public enum BindOpcode {

	BIND_OPCODE_DONE(0x00),
	BIND_OPCODE_SET_DYLIB_ORDINAL_IMM(0x10),
	BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB(0x20),
	BIND_OPCODE_SET_DYLIB_SPECIAL_IMM(0x30),
	BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM(0x40),
	BIND_OPCODE_SET_TYPE_IMM(0x50),
	BIND_OPCODE_SET_ADDEND_SLEB(0x60),
	BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB(0x70),
	BIND_OPCODE_ADD_ADDR_ULEB(0x80),
	BIND_OPCODE_DO_BIND(0x90),
	BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB(0xA0),
	BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED(0xB0),
	BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB(0xC0),
	BIND_OPCODE_THREADED(0xD0);

	private int opcode;

	/**
	 * Creates a new {@link BindOpcode} for the given opcode value
	 * 
	 * @param opcode The opcode value
	 */
	private BindOpcode(int opcode) {
		this.opcode = opcode;
	}

	/**
	 * {@return the opcode value}
	 */
	public int getOpcode() {
		return opcode;
	}

	/**
	 * {@return a new data type from this enum}
	 */
	public static DataType toDataType() {
		EnumDataType enumDataType = new EnumDataType("bind_opcode", 1);
		enumDataType.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		for (BindOpcode bindOpcode : BindOpcode.values()) {
			enumDataType.add(bindOpcode.toString(), bindOpcode.getOpcode());
		}
		return enumDataType;
	}

	/**
	 * Gets the {@link BindOpcode} that corresponds to the given opcode value
	 * 
	 * @param opcode The opcode value
	 * @return The {@link BindOpcode} that corresponds to the given opcode value, or null if it does
	 *   not exist
	 */
	public static BindOpcode forOpcode(int opcode) {
		for (BindOpcode bindOpcode : BindOpcode.values()) {
			if (bindOpcode.getOpcode() == opcode) {
				return bindOpcode;
			}
		}
		return null;
	}
}
