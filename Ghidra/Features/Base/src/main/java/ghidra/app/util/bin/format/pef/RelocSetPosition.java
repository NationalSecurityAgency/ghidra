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
package ghidra.app.util.bin.format.pef;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

/**
 * See Apple's -- PEFBinaryFormat.h
 */
public class RelocSetPosition extends Relocation {
	private int offset;

	RelocSetPosition(BinaryReader reader) throws IOException {
		int value = reader.readNextShort() & 0xffff;

		opcode   = ((value & 0xfc00) >> 10) & 0x3f;
		offset   =  (value & 0x03ff) << 16;
		offset  |=  (reader.readNextShort() & 0xffff);
	}

	@Override
	public boolean isMatch() {
		return opcode == 0x28;
	}

	@Override
	public int getSizeInBytes() {
		return 4;
	}

	public int getOffset() {
		return offset;
	}

	@Override
	public void apply(ImportStateCache importState, RelocationState relocState, 
			ContainerHeader header, Program program, MessageLog log, TaskMonitor monitor) {

		Address offsetAddress = relocState.getSectionToBeRelocated().add(offset & 0xffffffff);
		relocState.setRelocationAddress(offsetAddress);
	}
}
