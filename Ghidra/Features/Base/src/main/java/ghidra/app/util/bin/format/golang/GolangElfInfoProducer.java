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
package ghidra.app.util.bin.format.golang;

import java.util.Map;
import java.util.Map.Entry;

import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.info.ElfInfoItem;
import ghidra.app.util.bin.format.elf.info.ElfInfoItem.ReaderFunc;
import ghidra.app.util.bin.format.elf.info.ElfInfoProducer;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Handles marking up and program info for Golang binaries.
 * <ul>
 *   <li>NoteGoBuildId</li>
 * 	 <li>GoBuildInfo</li>
 *   <li>
 *     <ul>
 *       <li>Go version</li>
 *       <li>App path, main package</li>
 *       <li>Module dependency list</li>
 *       <li>Build settings / flags</li>
 *     </ul>
 *   </li>
 * </ul>
 */
public class GolangElfInfoProducer implements ElfInfoProducer {
	private static final Map<String, ReaderFunc<ElfInfoItem>> GOLANGINFO_READERS = Map.of(
		GoBuildInfo.ELF_SECTION_NAME, GoBuildInfo::read,
		NoteGoBuildId.SECTION_NAME, NoteGoBuildId::read);

	private ElfLoadHelper elfLoadHelper;

	@Override
	public void init(ElfLoadHelper newElfLoadHelper) {
		this.elfLoadHelper = newElfLoadHelper;
	}

	@Override
	public void markupElfInfo(TaskMonitor monitor) throws CancelledException {
		Program program = elfLoadHelper.getProgram();

		for (Entry<String, ReaderFunc<ElfInfoItem>> itemEntry : GOLANGINFO_READERS.entrySet()) {
			monitor.checkCancelled();

			String sectionName = itemEntry.getKey();
			ReaderFunc<ElfInfoItem> readFunc = itemEntry.getValue();

			ElfInfoItem.markupElfInfoItemSection(program, sectionName, readFunc);
		}
	}

}
