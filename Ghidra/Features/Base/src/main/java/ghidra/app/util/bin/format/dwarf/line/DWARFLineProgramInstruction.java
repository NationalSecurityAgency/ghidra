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

import java.util.List;

public record DWARFLineProgramInstruction(long offset, String instr, List<Number> operands,
		DWARFLineProgramState row) {

	public String getDesc() {
		if (row != null) {
			String flags = (row.isBasicBlock ? " basic block " : "") +
				(row.isEndSequence ? " end-of-seq " : "") + (row.isStatement ? " statement " : "") +
				(row.prologueEnd ? " prologue-end " : "");
			return "[%04x] %s %s - 0x%x, file: %d, line: %d, %s".formatted(offset, instr, operands,
				row.address, row.file, row.line, flags);
		}
		return "[%04x] %s %s".formatted(offset, instr, operands);
	}

}
