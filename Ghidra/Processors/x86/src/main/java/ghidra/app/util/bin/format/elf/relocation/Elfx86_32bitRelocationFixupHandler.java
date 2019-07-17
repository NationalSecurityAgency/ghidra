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

public class Elfx86_32bitRelocationFixupHandler extends RelocationFixupHandler {

	@Override
	public boolean processRelocation(Program program, Relocation relocation, Address oldImageBase,
			Address newImageBase) throws MemoryAccessException, CodeUnitInsertionException {

		switch (relocation.getType()) {
			case X86_32_ElfRelocationConstants.R_386_NONE:
			case X86_32_ElfRelocationConstants.R_386_32:
			case X86_32_ElfRelocationConstants.R_386_PC32:
			case X86_32_ElfRelocationConstants.R_386_GOT32:
			case X86_32_ElfRelocationConstants.R_386_PLT32:
			case X86_32_ElfRelocationConstants.R_386_COPY:
			case X86_32_ElfRelocationConstants.R_386_GLOB_DAT:
			case X86_32_ElfRelocationConstants.R_386_JMP_SLOT:
			case X86_32_ElfRelocationConstants.R_386_RELATIVE:
			case X86_32_ElfRelocationConstants.R_386_GOTOFF:
			case X86_32_ElfRelocationConstants.R_386_GOTPC:

			case X86_32_ElfRelocationConstants.R_386_TLS_TPOFF:
			case X86_32_ElfRelocationConstants.R_386_TLS_IE:
			case X86_32_ElfRelocationConstants.R_386_TLS_GOTIE:
			case X86_32_ElfRelocationConstants.R_386_TLS_LE:
			case X86_32_ElfRelocationConstants.R_386_TLS_GD:
			case X86_32_ElfRelocationConstants.R_386_TLS_LDM:
			case X86_32_ElfRelocationConstants.R_386_TLS_GD_32:
			case X86_32_ElfRelocationConstants.R_386_TLS_GD_PUSH:
			case X86_32_ElfRelocationConstants.R_386_TLS_GD_CALL:
			case X86_32_ElfRelocationConstants.R_386_TLS_GD_POP:
			case X86_32_ElfRelocationConstants.R_386_TLS_LDM_32:
			case X86_32_ElfRelocationConstants.R_386_TLS_LDM_PUSH:
			case X86_32_ElfRelocationConstants.R_386_TLS_LDM_CALL:
			case X86_32_ElfRelocationConstants.R_386_TLS_LDM_POP:
			case X86_32_ElfRelocationConstants.R_386_TLS_LDO_32:
			case X86_32_ElfRelocationConstants.R_386_TLS_IE_32:
			case X86_32_ElfRelocationConstants.R_386_TLS_LE_32:
			case X86_32_ElfRelocationConstants.R_386_TLS_DTPMOD32:
			case X86_32_ElfRelocationConstants.R_386_TLS_DTPOFF32:
			case X86_32_ElfRelocationConstants.R_386_TLS_TPOFF32:
				return process32BitRelocation(program, relocation, oldImageBase, newImageBase);
		}
		return false;

	}

	@Override
	public boolean handlesProgram(Program program) {
		if (!ElfLoader.ELF_NAME.equals(program.getExecutableFormat())) {
			return false;
		}
		Language language = program.getLanguage();
		if (language.getLanguageDescription().getSize() != 32) {
			return false;
		}
		Processor processor = language.getProcessor();
		return (processor.equals(Processor.findOrPossiblyCreateProcessor("x86")));
	}

}
