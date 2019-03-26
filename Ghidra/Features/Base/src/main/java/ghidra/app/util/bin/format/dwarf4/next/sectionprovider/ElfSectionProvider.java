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
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.listing.Program;

import java.io.File;
import java.io.IOException;

import generic.continues.RethrowContinuesFactory;

/**
 * Fetches DWARF section data from ELF files, directly, without going through
 * the Ghidra memory block api.  This section provider usually isn't needed as
 * ELF sections are normally provided as Ghidra memory blocks.  In case of extra-
 * large binaries, Ghidra may not be able to map the debug sections into memory
 * and this section provider will allow the DWARF analyzer to still function. 
 */
public class ElfSectionProvider implements DWARFSectionProvider {

	private ElfHeader header;
	private RandomAccessByteProvider provider;

	public static ElfSectionProvider createSectionProviderFor(Program program) {
		if (ElfLoader.ELF_NAME.equals(program.getExecutableFormat())) {
			try {
				File exePath = new File(program.getExecutablePath());
				return new ElfSectionProvider(exePath);
			}
			catch (IOException ioe) {
				// ignore
			}
		}
		return null;
	}

	public ElfSectionProvider(File exeFile) throws IOException {
		provider = new RandomAccessByteProvider(exeFile);
		try {
			// Parse the ELF header to get the sections
			header = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, provider);
			header.parse();
		}
		catch (ElfException e) {
			provider.close();
			throw new IOException("Error parsing ELF", e);
		}
	}

	@Override
	public ByteProvider getSectionAsByteProvider(String sectionName) throws IOException {

		ElfSectionHeader section = header.getSection("." + sectionName);

		return (section != null) ? new ByteProviderWrapper(section.getReader().getByteProvider(),
			section.getOffset(), section.getSize()) : null;
	}

	@Override
	public void close() {
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
			if (header.getSection("." + sectionName) == null) {
				return false;
			}
		}
		return true;
	}

}
