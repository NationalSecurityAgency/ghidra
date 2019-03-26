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
package ghidra.app.util.bin.format.elf.relocation;

import ghidra.app.plugin.core.reloc.RelocationFixupHandler;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.util.CodeUnitInsertionException;

public class Elfx86_64bitRelocationFixupHandler extends RelocationFixupHandler {

	@Override
	public boolean processRelocation(Program program, Relocation relocation, Address oldImageBase,
			Address newImageBase) throws MemoryAccessException, CodeUnitInsertionException {

		switch (relocation.getType()) {
			case X86_64_ElfRelocationConstants.R_X86_64_NONE:
			case X86_64_ElfRelocationConstants.R_X86_64_64:
			case X86_64_ElfRelocationConstants.R_X86_64_PC32:
			case X86_64_ElfRelocationConstants.R_X86_64_GOT32:
			case X86_64_ElfRelocationConstants.R_X86_64_PLT32:
			case X86_64_ElfRelocationConstants.R_X86_64_COPY:
			case X86_64_ElfRelocationConstants.R_X86_64_GLOB_DAT:
			case X86_64_ElfRelocationConstants.R_X86_64_JUMP_SLOT:
			case X86_64_ElfRelocationConstants.R_X86_64_RELATIVE:
			case X86_64_ElfRelocationConstants.R_X86_64_GOTPCREL:
			case X86_64_ElfRelocationConstants.R_X86_64_32:
			case X86_64_ElfRelocationConstants.R_X86_64_32S:
			case X86_64_ElfRelocationConstants.R_X86_64_16:
			case X86_64_ElfRelocationConstants.R_X86_64_PC16:
			case X86_64_ElfRelocationConstants.R_X86_64_8:
			case X86_64_ElfRelocationConstants.R_X86_64_PC8:
			case X86_64_ElfRelocationConstants.R_X86_64_DTPMOD64:
			case X86_64_ElfRelocationConstants.R_X86_64_DTPOFF64:
			case X86_64_ElfRelocationConstants.R_X86_64_TPOFF64:
			case X86_64_ElfRelocationConstants.R_X86_64_TLSGD:
			case X86_64_ElfRelocationConstants.R_X86_64_TLSLD:
			case X86_64_ElfRelocationConstants.R_X86_64_DTPOFF32:
			case X86_64_ElfRelocationConstants.R_X86_64_GOTTPOFF:
			case X86_64_ElfRelocationConstants.R_X86_64_TPOFF32:
			case X86_64_ElfRelocationConstants.R_X86_64_PC64:
			case X86_64_ElfRelocationConstants.R_X86_64_GOTOFF64:
			case X86_64_ElfRelocationConstants.R_X86_64_GOTPC32:
			case X86_64_ElfRelocationConstants.R_X86_64_GOT64:
			case X86_64_ElfRelocationConstants.R_X86_64_GOTPCREL64:
			case X86_64_ElfRelocationConstants.R_X86_64_GOTPC64:
			case X86_64_ElfRelocationConstants.R_X86_64_GOTPLT64:
			case X86_64_ElfRelocationConstants.R_X86_64_PLTOFF64:
			case X86_64_ElfRelocationConstants.R_X86_64_SIZE32:
			case X86_64_ElfRelocationConstants.R_X86_64_SIZE64:
			case X86_64_ElfRelocationConstants.R_X86_64_GOTPC32_TLSDESC:
			case X86_64_ElfRelocationConstants.R_X86_64_TLSDESC_CALL:
			case X86_64_ElfRelocationConstants.R_X86_64_TLSDESC:
			case X86_64_ElfRelocationConstants.R_X86_64_IRELATIVE:
			case X86_64_ElfRelocationConstants.R_X86_64_RELATIVE64:
			case X86_64_ElfRelocationConstants.R_X86_64_NUM:
			case X86_64_ElfRelocationConstants.R_X86_64_GNU_VTINHERIT:
			case X86_64_ElfRelocationConstants.R_X86_64_GNU_VTENTRY:
				return process64BitRelocation(program, relocation, oldImageBase, newImageBase);
		}
		return false;
	}

	@Override
	public boolean handlesProgram(Program program) {
		if (!ElfLoader.ELF_NAME.equals(program.getExecutableFormat())) {
			return false;
		}
		Language language = program.getLanguage();
		if (language.getLanguageDescription().getSize() != 64) {
			return false;
		}
		Processor processor = language.getProcessor();
		return (processor.equals(Processor.findOrPossiblyCreateProcessor("x86")));
	}

}
