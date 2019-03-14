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
package ghidra.app.util.bin.format.dwarf4.next.sectionprovider;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

import java.io.IOException;

/**
 * Fetches DWARF sections from a normal program using simple Ghidra memory blocks. 
 */
public class BaseSectionProvider implements DWARFSectionProvider {
	private Program program;

	public static BaseSectionProvider createSectionProviderFor(Program program) {
		return new BaseSectionProvider(program);
	}

	public BaseSectionProvider(Program program) {
		this.program = program;
	}

	@Override
	public ByteProvider getSectionAsByteProvider(String sectionName) throws IOException {

		MemoryBlock block = program.getMemory().getBlock(sectionName);
		if (block == null) {
			block = program.getMemory().getBlock("." + sectionName);
		}
		if (block != null) {
			// TODO: limit the returned ByteProvider to block.getSize() bytes
			return new MemoryByteProvider(program.getMemory(), block.getStart());
		}

		return null;
	}

	@Override
	public boolean hasSection(String... sectionNames) {
		for (String sectionName : sectionNames) {
			if (program.getMemory().getBlock(sectionName) == null &&
				program.getMemory().getBlock("." + sectionName) == null) {
				return false;
			}
		}
		return true;
	}

	@Override
	public void close() {
		// nothing
	}

}
