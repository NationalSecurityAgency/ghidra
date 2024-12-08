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
 * Rebase opcodes
 * 
 * @see <a href="https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h">EXTERNAL_HEADERS/mach-o/loader.h</a> 
 */
public enum RebaseOpcode {

	REBASE_OPCODE_DONE(0x00),
	REBASE_OPCODE_SET_TYPE_IMM(0x10),
	REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB(0x20),
	REBASE_OPCODE_ADD_ADDR_ULEB(0x30),
	REBASE_OPCODE_ADD_ADDR_IMM_SCALED(0x40),
	REBASE_OPCODE_DO_REBASE_IMM_TIMES(0x50),
	REBASE_OPCODE_DO_REBASE_ULEB_TIMES(0x60),
	REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB(0x70),
	REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB(0x80);

	private int opcode;

	/**
	 * Creates a new {@link RebaseOpcode} for the given opcode value
	 * 
	 * @param opcode The opcode value
	 */
	private RebaseOpcode(int opcode) {
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
		EnumDataType enumDataType = new EnumDataType("rebase_opcode", 1);
		enumDataType.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		for (RebaseOpcode rebaseOpcode : RebaseOpcode.values()) {
			enumDataType.add(rebaseOpcode.toString(), rebaseOpcode.getOpcode());
		}
		return enumDataType;
	}

	/**
	 * Gets the {@link RebaseOpcode} that corresponds to the given opcode value
	 * 
	 * @param opcode The opcode value
	 * @return The {@link RebaseOpcode} that corresponds to the given opcode value, or null if it 
	 *   does not exist
	 */
	public static RebaseOpcode forOpcode(int opcode) {
		for (RebaseOpcode rebaseOpcode : RebaseOpcode.values()) {
			if (rebaseOpcode.getOpcode() == opcode) {
				return rebaseOpcode;
			}
		}
		return null;
	}
}

