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

import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.List;

public class ClassicLazyBindProcessor extends AbstractClassicProcessor {

	public ClassicLazyBindProcessor(MachHeader header, Program program) {
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
			List<Section> sections = header.getAllSections();
			for (Section section : sections) {
				if (monitor.isCancelled()) {
					return;
				}
				if (section.getSize() == 0) {
					continue;
				}
				int sectionType = section.getFlags() & SectionTypes.SECTION_TYPE_MASK;
				if (sectionType == SectionTypes.S_LAZY_SYMBOL_POINTERS) {
					int indirectOffset = section.getReserved1();
					long count = section.getSize() / program.getDefaultPointerSize();
					for (int i = 0; i < count; ++i) {
						int symbolIndex = command.getIndirectSymbols()[indirectOffset + i];
						NList nList = symbolTableCommand.getSymbolAt(symbolIndex);
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
				else if ((sectionType == SectionTypes.S_SYMBOL_STUBS) &&
					(((section.getFlags() & SectionAttributes.S_ATTR_SELF_MODIFYING_CODE) != 0)) &&
					(section.getReserved2() == 5)) {
					int indirectOffset = section.getReserved1();
					long count = section.getSize() / 5;
					for (int i = 0; i < count; ++i) {
						int symbolIndex = command.getIndirectSymbols()[indirectOffset + i];
						if (symbolIndex != DynamicSymbolTableConstants.INDIRECT_SYMBOL_ABS) {
							NList nList = symbolTableCommand.getSymbolAt(symbolIndex);
							boolean isWeak =
								(nList.getDescription() & NListConstants.DESC_N_WEAK_REF) != 0;
							String fromDylib = getClassicOrdinalName(nList.getLibraryOrdinal());
							long address = section.getAddress() + (i * 5);
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
}
