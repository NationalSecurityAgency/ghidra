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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/**
 * See Apple's -- PEFBinaryFormat.h
 */
public class RelocLgSetOrBySection extends Relocation {
	/**
	 * This instruction adds the address of the instantiated
	 * section specified by <code>index</code> to the word
	 * pointed to by <code>relocAddress</code>. After
	 * execution, <code>relocAddress</code> points to just
	 * past the modified word.
	 */
	public final static int kPEFRelocLgBySection = 0;
	/**
	 * This instruction sets the variable <code>sectionC</code>
	 * to the memory address of the instantiated section
	 * specified by <code>index</code>.
	 */
	public final static int kPEFRelocLgSetSectC = 1;
	/**
	 * This instruction sets the variable <code>sectionD</code>
	 * to the memory adddress of the instantiated section
	 * specified by <code>index</code>.
	 */
	public final static int kPEFRelocLgSetSectD = 2;

	private int subopcode;
	private int index;

	RelocLgSetOrBySection(BinaryReader reader) throws IOException {
		int value = reader.readNextShort() & 0xffff;

		opcode    =  (value & 0xfc00) >> 10;
		subopcode =  (value & 0x03c0) >> 6;
		index     =  (value & 0x003f) << 16;
		index    |=  reader.readNextShort() & 0xffff;
	}

	@Override
	public boolean isMatch() {
		return opcode == 0x2d;
	}

	@Override
	public int getSizeInBytes() {
		return 4;
	}

	public int getSubopcode() {
		return subopcode;
	}

	public int getIndex() {
		return index;
	}

	@Override
	public String toString() {
		switch (subopcode) {
			case kPEFRelocLgBySection: return "RelocLgBySection";
			case kPEFRelocLgSetSectC:  return "RelocLgSetSectC";
			case kPEFRelocLgSetSectD:  return "RelocLgSetSectD";
		}
		return super.toString();
	}

	@Override
	public void apply(ImportStateCache importState, RelocationState relocState,
			ContainerHeader header, Program program, MessageLog log, TaskMonitor monitor) {

		switch (subopcode) {
			case kPEFRelocLgBySection: {
				SectionHeader sect = header.getSections().get(index);
				MemoryBlock block = importState.getMemoryBlockForSection(sect);
				relocState.relocateMemoryAt(relocState.getRelocationAddress(),
					(int) block.getStart().getOffset(), log);
				break;
			}
			case kPEFRelocLgSetSectC: {
				SectionHeader sectC = header.getSections().get(index);
				MemoryBlock blockC = importState.getMemoryBlockForSection(sectC);
				relocState.setSectionC(blockC.getStart());
				break;
			}
			case kPEFRelocLgSetSectD: {
				SectionHeader sectD = header.getSections().get(index);
				MemoryBlock blockD = importState.getMemoryBlockForSection(sectD);
				relocState.setSectionD(blockD.getStart());
				break;
			}
			default: {
				log.appendMsg("Unsupported RelocLgSetOrBySection subopcode: " + subopcode);
				break;
			}
		}
	}
}
