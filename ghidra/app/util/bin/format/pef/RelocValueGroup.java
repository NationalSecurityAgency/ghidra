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

import ghidra.app.cmd.label.AddUniqueLabelCmd;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.List;

/**
 * See Apple's -- PEFBinaryFormat.h
 */
public class RelocValueGroup extends Relocation {

	public final static int kPEFRelocBySectC = 0;
	public final static int kPEFRelocBySectD = 1;
	public final static int kPEFRelocTVector12 = 2;
	public final static int kPEFRelocTVector8 = 3;
	public final static int kPEFRelocVTable8 = 4;
	public final static int kPEFRelocImportRun = 5;

	private int subopcode;
	private int runLength;

	RelocValueGroup(BinaryReader reader) throws IOException {
		int value = reader.readNextShort() & 0xffff;

		opcode    = (value & 0xe000) >> 13;
		subopcode = (value & 0x1e00) >> 9;
		runLength = (value & 0x01ff);
	}

	@Override
	public boolean isMatch() {
		return opcode == 0x2;
	}

	public int getSubopcode() {
		return subopcode;
	}

	public int getRunLength() {
		return runLength + 1;
	}

	@Override
	public String toString() {
		switch (subopcode) {
			case kPEFRelocBySectC:   return "RelocBySectC";
			case kPEFRelocBySectD:   return "RelocBySectD";
			case kPEFRelocTVector12: return "RelocTVector12";
			case kPEFRelocTVector8:  return "RelocTVector8";
			case kPEFRelocVTable8:   return "RelocVTable8";
			case kPEFRelocImportRun: return "RelocImportRun";
		}
		return super.toString();
	}

	@Override
	public void apply(ImportStateCache importState, RelocationState relocState, 
			ContainerHeader header, Program program, MessageLog log, TaskMonitor monitor) {
		List<ImportedSymbol> importedSymbols = header.getLoader().getImportedSymbols();

		switch (subopcode) {
			case RelocValueGroup.kPEFRelocBySectC: {
				for (int i = 0 ; i < runLength + 1 ; ++i) {
					if (monitor.isCancelled()) {
						return;
					}
					relocState.relocateMemoryAt(relocState.getRelocationAddress(), 
												(int)relocState.getSectionC().getOffset(), log);
					relocState.incrementRelocationAddress(4);
				}
				break;
			}
			case RelocValueGroup.kPEFRelocBySectD: {
				for (int i = 0 ; i < runLength + 1 ; ++i) {
					if (monitor.isCancelled()) {
						return;
					}
					relocState.relocateMemoryAt(relocState.getRelocationAddress(), 
												(int)relocState.getSectionD().getOffset(), log);
					relocState.incrementRelocationAddress(4);
				}
				break;
			}
			case RelocValueGroup.kPEFRelocTVector12: {
				for (int i = 0 ; i < runLength + 1 ; ++i) {
					if (monitor.isCancelled()) {
						return;
					}
					relocState.relocateMemoryAt(relocState.getRelocationAddress(), 
												(int)relocState.getSectionC().getOffset(), log);
					relocState.incrementRelocationAddress(4);

					relocState.relocateMemoryAt(relocState.getRelocationAddress(), 
												(int)relocState.getSectionD().getOffset(), log);
					relocState.incrementRelocationAddress(4);

					relocState.incrementRelocationAddress(4);
				}
				break;
			}
			case RelocValueGroup.kPEFRelocTVector8: {
				for (int i = 0 ; i < runLength + 1 ; ++i) {
					if (monitor.isCancelled()) {
						return;
					}
					relocState.relocateMemoryAt(relocState.getRelocationAddress(), 
												(int)relocState.getSectionC().getOffset(), log);
					relocState.incrementRelocationAddress(4);

					relocState.relocateMemoryAt(relocState.getRelocationAddress(), 
												(int)relocState.getSectionD().getOffset(), log);

					if (importState.getTocAddress() == null) {
						try {
							Address relocationAddress = relocState.getRelocationAddress();
							int tocAddressValue = program.getMemory().getInt(relocationAddress);
							AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
							Address tocAddress = space.getAddress(tocAddressValue & 0xffffffffL);
							importState.setTocAddress(tocAddress);
						}
						catch (MemoryAccessException e) {}
					}

					relocState.incrementRelocationAddress(4);
				}
				break;
			}
			case RelocValueGroup.kPEFRelocVTable8: {
				for (int i = 0 ; i < runLength + 1 ; ++i) {
					if (monitor.isCancelled()) {
						return;
					}
					relocState.relocateMemoryAt(relocState.getRelocationAddress(), 
												(int)relocState.getSectionD().getOffset(), log);
					relocState.incrementRelocationAddress(8);
				}
				break;
			}
			case RelocValueGroup.kPEFRelocImportRun: {
				for (int i = 0 ; i < runLength + 1 ; ++i) {
					if (monitor.isCancelled()) {
						return;
					}

					ImportedLibrary library = header.getLoader().findLibrary(relocState.getImportIndex());
					ImportedSymbol importedSymbol = importedSymbols.get(relocState.getImportIndex());

					Namespace namespace = importState.getTVectNamespace();

					String name = SymbolUtilities.replaceInvalidChars(importedSymbol.getName(), true);
					AddUniqueLabelCmd cmd = new AddUniqueLabelCmd(relocState.getRelocationAddress(), name, namespace, SourceType.IMPORTED);
					if (!cmd.applyTo(program)) {
						log.appendMsg(cmd.getStatusMsg());
					}

					Symbol symbol = importState.getSymbol(name, library);
					relocState.fixupMemory(relocState.getRelocationAddress(), symbol.getAddress(), log);

					relocState.incrementRelocationAddress(4);
					relocState.incrementImportIndex();
				}
				break;
			}
			default: {
				log.appendMsg("Unsupported RelocValueGroup subopcode: "+subopcode);
				break;
			}
		}
	}
}
