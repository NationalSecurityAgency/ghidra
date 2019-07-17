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
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.List;

/**
 *  See Apple's -- PEFBinaryFormat.h
 */
public class RelocByIndexGroup extends Relocation {
	/**
	 * This "RelocSmByImport" (SYMB) instruction adds the address of the imported symbol 
	 * whose index is held in <code>index</code> to the word pointed to by 
	 * <code>relocAddress</code>. After the addition, <code>relocAddress</code> 
	 * points to just past the modified word, and <code>importindex</code> 
	 * is set to <code>index+1</code>.
	 */
	public final static int kPEFRelocSmByImport = 0;
	/**
	 * This "RelocSmSetSectC" (CDIS) instruction sets the variable <code>sectionC</code> 
	 * to the memory address of the instantiated section 
	 * specified by <code>index</code>.
	 */
	public final static int kPEFRelocSmSetSectC = 1;
	/**
	 * This "RelocSmSetSectD" (DTIS) instruction sets the variable <code>sectionD</code>
	 * to the memory adddress of the instantiated section 
	 * specified by <code>index</code>.
	 */
	public final static int kPEFRelocSmSetSectD = 2;
	/**
	 * This "RelocSmBySection" (SECN) instruction adds the address of the instantiated 
	 * section specified by <code>index</code> to the word 
	 * pointed to by <code>relocAddress</code>. After
	 * execution, <code>relocAddress</code> points to just 
	 * past the modified word.
	 */
	public final static int kPEFRelocSmBySection = 3;

	private int subopcode;
	private int index;

	RelocByIndexGroup(BinaryReader reader) throws IOException {
		int value = reader.readNextShort() & 0xffff;

		opcode    =  (value & 0xe000) >> 13;
		subopcode =  (value & 0x1e00) >>  9;
		index     =  (value & 0x01ff);
	}

	@Override
	public boolean isMatch() {
		return opcode == 0x3;
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
			case kPEFRelocSmByImport:  return "RelocSmByImport";
			case kPEFRelocSmSetSectC:  return "RelocSmSetSectC";
			case kPEFRelocSmSetSectD:  return "RelocSmSetSectD";
			case kPEFRelocSmBySection: return "RelocSmBySection";
		}
		return super.toString();
	}

	@Override
	public void apply(ImportStateCache importState, RelocationState relocState, 
			ContainerHeader header, Program program, MessageLog log, TaskMonitor monitor) {

		List<ImportedSymbol> importedSymbols = header.getLoader().getImportedSymbols();

		switch (subopcode) {
			case RelocByIndexGroup.kPEFRelocSmByImport: {
				ImportedSymbol importedSymbol = importedSymbols.get(index);
				ImportedLibrary library = header.getLoader().findLibrary(index);
				String importedSymbolName = SymbolUtilities.replaceInvalidChars(importedSymbol.getName(), true);
				Symbol symbol = importState.getSymbol(importedSymbolName, library);
				relocState.relocateMemoryAt(relocState.getRelocationAddress(), 
											(int)symbol.getAddress().getOffset(), log);
				relocState.incrementRelocationAddress(4);
				relocState.setImportIndex(index + 1);
				break;
			}
			case RelocByIndexGroup.kPEFRelocSmSetSectC: {
				SectionHeader sectC = header.getSections().get(index);
				MemoryBlock blockC = importState.getMemoryBlockForSection(sectC);
				relocState.setSectionC(blockC.getStart());
				break;
			}
			case RelocByIndexGroup.kPEFRelocSmSetSectD: {
				SectionHeader sectD = header.getSections().get(index);
				MemoryBlock blockD = importState.getMemoryBlockForSection(sectD);
				relocState.setSectionD(blockD.getStart());
				break;
			}
			case RelocByIndexGroup.kPEFRelocSmBySection: {
				SectionHeader sect = header.getSections().get(index);
				MemoryBlock block = importState.getMemoryBlockForSection(sect);
				relocState.relocateMemoryAt(relocState.getRelocationAddress(), 
											(int)block.getStart().getOffset(), log);
				break;
			}
			default: {
				log.appendMsg("Unsupported RelocByIndexGroup subopcode: "+subopcode);
				break;
			}
		}
	}
}
