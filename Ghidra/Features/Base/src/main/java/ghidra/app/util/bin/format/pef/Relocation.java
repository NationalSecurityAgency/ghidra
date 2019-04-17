/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.pef;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

/**
 * The high-order 7 bits for the currently defined relocation opcode values.
 * 
 * Binary values indicated by "x" are "don't care" 
 * operands. For example, any combination of the high-order 7 bits that starts 
 * with two zero bits (00) indicates the RelocBySectDWithSkip instruction. 
 * 
 * Relocation instructions are stored in 2-byte relocation blocks. Most instructions 
 * take up one block that combines an opcode and related arguments. Instructions 
 * that are larger than 2 bytes have an opcode and some of the operands in the 
 * first 2-byte block, with other operands in the following 2-byte blocks. The 
 * opcode occupies the upper (higher-order) bits of the block that contains it. 
 * Relocation instructions can be decoded from the high-order 7 bits of their first 
 * block. 
 * 
 * All currently defined relocation instructions relocate locations as words 
 * (that is, 4-byte values).
 */
public abstract class Relocation implements StructConverter {
	protected int opcode;

	public abstract boolean isMatch();

	public abstract void apply(ImportStateCache importState, 
								RelocationState relocState, 
								ContainerHeader header, 
								Program program, 
								MessageLog log, TaskMonitor monitor);

	public int getOpcode() {
		return opcode;
	}

	public int getSizeInBytes() {
		return 2;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType dt = getSizeInBytes() == 2 ? WORD : DWORD;
		return new TypedefDataType(toString(), dt);
	}

	@Override
	public String toString() {
		String className = getClass().getName();
		int pos = className.lastIndexOf('.');
		if (pos == -1) {
			return className;
		}
		return className.substring(pos+1);
	}
}
