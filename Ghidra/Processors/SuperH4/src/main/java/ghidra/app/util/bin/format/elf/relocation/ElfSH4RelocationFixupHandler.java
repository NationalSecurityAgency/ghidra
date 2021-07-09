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

public class ElfSH4RelocationFixupHandler extends RelocationFixupHandler {

	@Override
	public boolean processRelocation(Program program, Relocation relocation, Address oldImageBase,
			Address newImageBase) throws MemoryAccessException, CodeUnitInsertionException {

		switch (relocation.getType()) {
			case SH_ElfRelocationConstants.R_SH_DIR32:
			case SH_ElfRelocationConstants.R_SH_REL32:
			case SH_ElfRelocationConstants.R_SH_GLOB_DAT:
			case SH_ElfRelocationConstants.R_SH_JMP_SLOT:
			case SH_ElfRelocationConstants.R_SH_RELATIVE:
				return process32BitRelocation(program, relocation, oldImageBase, newImageBase);

//			case SH_ElfRelocationConstants.R_SH_DIR8WPN:
//			case SH_ElfRelocationConstants.R_SH_DIR8WPZ:
//			case SH_ElfRelocationConstants.R_SH_IND12W:
//			case SH_ElfRelocationConstants.R_SH_DIR8WPL:

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
		return ("SuperH4".equals(processor.toString()) || "SuperH".equals(processor.toString()));
	}

}
