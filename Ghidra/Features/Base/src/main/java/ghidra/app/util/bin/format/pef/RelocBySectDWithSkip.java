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

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * See Apple's -- PEFBinaryFormat.h
 */
public class RelocBySectDWithSkip extends Relocation {
	private int skipCount;
	private int relocCount;

	RelocBySectDWithSkip(BinaryReader reader) throws IOException {
		int value  = reader.readNextShort() & 0xffff;

		opcode     = ((value & 0xc000) >> 14) & 0x3;
		skipCount  =  (value & 0x3fc0) >>  6;
		relocCount =  (value & 0x003f);
	}

	@Override
	public boolean isMatch() {
		return opcode == 0x0;
	}

	public int getSkipCount() {
		return skipCount;
	}

	public int getRelocCount() {
		return relocCount;
	}

	@Override
	public void apply(ImportStateCache importState, RelocationState relocState, 
			ContainerHeader header, Program program, MessageLog log, TaskMonitor monitor) {

		relocState.incrementRelocationAddress(skipCount * 4);

		for (int i = 0 ; i < relocCount ; ++i) {
			relocState.relocateMemoryAt(relocState.getRelocationAddress(), 
										(int)relocState.getSectionD().getOffset(), log);
			relocState.incrementRelocationAddress(4);
		}
	}

}
