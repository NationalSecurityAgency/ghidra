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

import java.util.List;

import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class ClassicBindProcessor extends AbstractClassicProcessor {

	public ClassicBindProcessor(MachHeader header, Program program) {
		super(header, program);
	}

	public void process(TaskMonitor monitor) throws Exception {

		SymbolTableCommand symbolTableCommand =
			header.getFirstLoadCommand(SymbolTableCommand.class);
		List<DynamicSymbolTableCommand> commands =
			header.getLoadCommands(DynamicSymbolTableCommand.class);
		for (DynamicSymbolTableCommand command : commands) {
			if (monitor.isCancelled()) {
				break;
			}
			List<RelocationInfo> relocations = command.getExternalRelocations();
			for (RelocationInfo relocation : relocations) {
				if (monitor.isCancelled()) {
					break;
				}
				long address = relocation.getAddress() + getRelocationBase();
				int symbolIndex = relocation.getValue();
				NList nList = symbolTableCommand.getSymbolAt(symbolIndex);
				boolean isWeak = (nList.getDescription() & NListConstants.DESC_N_WEAK_REF) != 0;
				String fromDylib = getClassicOrdinalName(nList.getLibraryOrdinal());
				Section section = getSectionName(address);
				if (section == null) {
					// TODO: couldn't handle relocation.
					continue;
				}
				String sectionName = section.getSectionName();
				String segmentName = section.getSegmentName();
				if ((header.getFlags() & MachHeaderFlags.MH_PREBOUND) != 0) {
					// um, why is this block EMPTY?
				}
				perform(segmentName, sectionName, address, fromDylib, nList, isWeak, monitor);
			}

			List<Section> sections = header.getAllSections();
			for (Section section : sections) {
				if (monitor.isCancelled()) {
					return;
				}
				if (section.getSize() == 0) {
					continue;
				}
				int sectionType = section.getFlags() & SectionTypes.SECTION_TYPE_MASK;
				if (sectionType != SectionTypes.S_NON_LAZY_SYMBOL_POINTERS) {
					continue;
				}
				int indirectOffset = section.getReserved1();
				long count = section.getSize() / program.getDefaultPointerSize();
				for (int i = 0; i < count; ++i) {
					int symbolIndex = command.getIndirectSymbols()[indirectOffset + i];
					if (symbolIndex != DynamicSymbolTableConstants.INDIRECT_SYMBOL_LOCAL) {
						NList nList = symbolTableCommand.getSymbolAt(symbolIndex);
						if (nList == null) {
							continue;
						}
						boolean isWeak =
							(nList.getDescription() & NListConstants.DESC_N_WEAK_REF) != 0;
						String fromDylib = getClassicOrdinalName(nList.getLibraryOrdinal());
						long address = section.getAddress() + (i * program.getDefaultPointerSize());
						String sectionName = section.getSectionName();
						String segmentName = section.getSegmentName();
						perform(segmentName, sectionName, address, fromDylib, nList, isWeak,
							monitor);
					}
				}
			}
		}
	}

}
