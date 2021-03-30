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

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.program.model.listing.Program;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import generic.continues.RethrowContinuesFactory;

/**
 * Fetches DWARF section data for a MachO program with co-located .dSYM folder. (ie. Mac OSX
 * binaries)
 */
public class DSymSectionProvider implements DWARFSectionProvider {
	private MachHeader machHeader;
	private Map<String, Section> machSectionsByName = new HashMap<>();
	private RandomAccessByteProvider provider;

	public static File getDSYMForProgram(Program program) {
		
		File exePath = new File(program.getExecutablePath());
		File dSymFile = new File(exePath.getParentFile(),
			exePath.getName() + ".dSYM/Contents/Resources/DWARF/" + exePath.getName());

		return dSymFile.isFile() ? dSymFile : null;
	}

	public static DSymSectionProvider createSectionProviderFor(Program program) {
		if (MachoLoader.MACH_O_NAME.equals(program.getExecutableFormat())) {
			File dsymFile = getDSYMForProgram(program);
			if (dsymFile != null) {
				try {
					return new DSymSectionProvider(dsymFile);
				}
				catch (IOException | MachException e) {
					// ignore
				}
			}
		}
		return null;
	}

	public DSymSectionProvider(File dsymFile) throws IOException, MachException {
		this.provider = new RandomAccessByteProvider(dsymFile);
		
		machHeader = MachHeader.createMachHeader(RethrowContinuesFactory.INSTANCE, provider);
		machHeader.parse();
		for (Section s : machHeader.getAllSections()) {
			// strip leading "_"'s from section name to normalize
			String fixedSectionName = s.getSectionName().replaceFirst("^_*", "");
			machSectionsByName.put(fixedSectionName, s);
		}
	}

	@Override
	public ByteProvider getSectionAsByteProvider(String sectionName) throws IOException {
		
		Section s = machSectionsByName.get(sectionName);
		return (s != null) ? new ByteProviderWrapper(provider,
			machHeader.getStartIndex() + s.getOffset(), s.getSize()) : null;
	}

	@Override
	public void close()
	{
		try {
			provider.close();
		}
		catch (IOException e) {
			// ignore
		}
	}

	@Override
	public boolean hasSection(String... sectionNames) {
		for (String sectionName : sectionNames) {
			if (machSectionsByName.get(sectionName) == null) {
				return false;
			}
		}
		return true;
	}
}
