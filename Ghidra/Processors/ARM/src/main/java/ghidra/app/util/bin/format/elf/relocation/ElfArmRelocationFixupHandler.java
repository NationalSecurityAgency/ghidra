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

public class ElfArmRelocationFixupHandler extends RelocationFixupHandler {

	@Override
	public boolean processRelocation(Program program, Relocation relocation, Address oldImageBase,
			Address newImageBase) throws MemoryAccessException, CodeUnitInsertionException {

		switch (relocation.getType()) {
			case ARM_ElfRelocationConstants.R_ARM_NONE:
			case ARM_ElfRelocationConstants.R_ARM_ABS32:
			case ARM_ElfRelocationConstants.R_ARM_REL32:
			case ARM_ElfRelocationConstants.R_ARM_GLOB_DAT:
//			case ARM_ElfRelocationConstants.R_ARM_JUMP_SLOT:
			case ARM_ElfRelocationConstants.R_ARM_RELATIVE:
			case ARM_ElfRelocationConstants.R_ARM_GOT_PLT32:
			case ARM_ElfRelocationConstants.R_ARM_CALL:
			case ARM_ElfRelocationConstants.R_ARM_JUMP24:
			case ARM_ElfRelocationConstants.R_ARM_THM_JUMP24:
				return process32BitRelocation(program, relocation, oldImageBase, newImageBase);

//			case ARM_ElfRelocationConstants.R_ARM_PC24:
//			case ARM_ElfRelocationConstants.R_ARM_LDR_PC_G0:
//			case ARM_ElfRelocationConstants.R_ARM_ABS16:
//			case ARM_ElfRelocationConstants.R_ARM_ABS12:
//			case ARM_ElfRelocationConstants.R_ARM_THM_ABS5:
//			case ARM_ElfRelocationConstants.R_ARM_ABS_8:
//			case ARM_ElfRelocationConstants.R_ARM_SBREL32:
//			case ARM_ElfRelocationConstants.R_ARM_THM_CALL:
//			case ARM_ElfRelocationConstants.R_ARM_THM_PC8:
//			case ARM_ElfRelocationConstants.R_ARM_BREL_ADJ:
//			case ARM_ElfRelocationConstants.R_ARM_TLS_DESC:
//			case ARM_ElfRelocationConstants.R_ARM_THM_SWI8:
//			case ARM_ElfRelocationConstants.R_ARM_XPC25:
//			case ARM_ElfRelocationConstants.R_ARM_THM_XPC22:
//			case ARM_ElfRelocationConstants.R_ARM_TLS_DTPMOD32:
//			case ARM_ElfRelocationConstants.R_ARM_TLS_DTPOFF32:
//			case ARM_ElfRelocationConstants.R_ARM_TLS_TPOFF32:
//			case ARM_ElfRelocationConstants.R_ARM_COPY:
//			case ARM_ElfRelocationConstants.R_ARM_GOTOFF32:
//			case ARM_ElfRelocationConstants.R_ARM_BASE_PREL:
//			case ARM_ElfRelocationConstants.R_ARM_GOT_BREL:
//			case ARM_ElfRelocationConstants.R_ARM_BASE_ABS:
//			case ARM_ElfRelocationConstants.R_ARM_ALU_PCREL_7_0:
//			case ARM_ElfRelocationConstants.R_ARM_ALU_PCREL_15_8:
//			case ARM_ElfRelocationConstants.R_ARM_ALU_PCREL_23_15:
//			case ARM_ElfRelocationConstants.R_ARM_LDR_SBREL_11_0_NC:
//			case ARM_ElfRelocationConstants.R_ARM_ALU_SBREL_19_12_NC:
//			case ARM_ElfRelocationConstants.R_ARM_ALU_SBREL_27_20_CK:
//			case ARM_ElfRelocationConstants.R_ARM_TARGET1:
//			case ARM_ElfRelocationConstants.R_ARM_SBREL31:
//			case ARM_ElfRelocationConstants.R_ARM_V4BX:
//			case ARM_ElfRelocationConstants.R_ARM_TARGET2:
//			case ARM_ElfRelocationConstants.R_ARM_PREL31:
//			case ARM_ElfRelocationConstants.R_ARM_MOVW_ABS_NC:
//			case ARM_ElfRelocationConstants.R_ARM_MOVT_ABS:
//			case ARM_ElfRelocationConstants.R_ARM_MOVW_PREL_NC:
//			case ARM_ElfRelocationConstants.R_ARM_MOVT_PREL:
//			case ARM_ElfRelocationConstants.R_ARM_THM_MOVW_ABS_NC:
//			case ARM_ElfRelocationConstants.R_ARM_THM_MOVT_ABS:
//			case ARM_ElfRelocationConstants.R_ARM_THM_MOVW_PREL_NC:
//			case ARM_ElfRelocationConstants.R_ARM_THM_MOVT_PREL:
//			case ARM_ElfRelocationConstants.R_ARM_THM_JUMP19:
//			case ARM_ElfRelocationConstants.R_ARM_THM_JUMP6:
//			case ARM_ElfRelocationConstants.R_ARM_THM_ALU_PREL_11_0:
//			case ARM_ElfRelocationConstants.R_ARM_THM_PC12:
//			case ARM_ElfRelocationConstants.R_ARM_ABS32_NOI:
//			case ARM_ElfRelocationConstants.R_ARM_REL32_NOI:
//			case ARM_ElfRelocationConstants.R_ARM_ALU_PC_G0_NC:
//			case ARM_ElfRelocationConstants.R_ARM_ALU_PC_G0:
//			case ARM_ElfRelocationConstants.R_ARM_ALU_PC_G1_NC:
//			case ARM_ElfRelocationConstants.R_ARM_ALU_PC_G1:
//			case ARM_ElfRelocationConstants.R_ARM_ALU_PC_G2:
//			case ARM_ElfRelocationConstants.R_ARM_LDR_PC_G1:
//			case ARM_ElfRelocationConstants.R_ARM_LDR_PC_G2:
//			case ARM_ElfRelocationConstants.R_ARM_LDRS_PC_G0:
//			case ARM_ElfRelocationConstants.R_ARM_LDRS_PC_G1:
//			case ARM_ElfRelocationConstants.R_ARM_LDRS_PC_G2:
//			case ARM_ElfRelocationConstants.R_ARM_LDC_PC_G0:
//			case ARM_ElfRelocationConstants.R_ARM_LDC_PC_G1:
//			case ARM_ElfRelocationConstants.R_ARM_LDC_PC_G2:
//			case ARM_ElfRelocationConstants.R_ARM_ALU_SB_G0_NC:
//			case ARM_ElfRelocationConstants.R_ARM_ALU_SB_G0:
//			case ARM_ElfRelocationConstants.R_ARM_ALU_SB_G1_NC:
//			case ARM_ElfRelocationConstants.R_ARM_ALU_SB_G1:
//			case ARM_ElfRelocationConstants.R_ARM_ALU_SB_G2:
//			case ARM_ElfRelocationConstants.R_ARM_LDR_SB_G0:
//			case ARM_ElfRelocationConstants.R_ARM_LDR_SB_G1:
//			case ARM_ElfRelocationConstants.R_ARM_LDR_SB_G2:
//			case ARM_ElfRelocationConstants.R_ARM_LDRS_SB_G0:
//			case ARM_ElfRelocationConstants.R_ARM_LDRS_SB_G1:
//			case ARM_ElfRelocationConstants.R_ARM_LDRS_SB_G2:
//			case ARM_ElfRelocationConstants.R_ARM_LDC_SB_G0:
//			case ARM_ElfRelocationConstants.R_ARM_LDC_SB_G1:
//			case ARM_ElfRelocationConstants.R_ARM_LDC_SB_G2:
//			case ARM_ElfRelocationConstants.R_ARM_MOVW_BREL_NC:
//			case ARM_ElfRelocationConstants.R_ARM_MOVT_BREL:
//			case ARM_ElfRelocationConstants.R_ARM_MOVW_BREL:
//			case ARM_ElfRelocationConstants.R_ARM_THM_MOVW_BREL_NC:
//			case ARM_ElfRelocationConstants.R_ARM_THM_MOVT_BREL:
//			case ARM_ElfRelocationConstants.R_ARM_THM_MOVW_BREL:
//			case ARM_ElfRelocationConstants.R_ARM_TLS_GOTDESC:
//			case ARM_ElfRelocationConstants.R_ARM_TLS_CALL:
//			case ARM_ElfRelocationConstants.R_ARM_TLS_DESCSEQ:
//			case ARM_ElfRelocationConstants.R_ARM_THM_TLS_CALL:
//			case ARM_ElfRelocationConstants.R_ARM_PLT32_ABS:
//			case ARM_ElfRelocationConstants.R_ARM_GOT_ABS:
//			case ARM_ElfRelocationConstants.R_ARM_GOT_PREL:
//			case ARM_ElfRelocationConstants.R_ARM_GOT_BREL12:
//			case ARM_ElfRelocationConstants.R_ARM_GOTOFF12:
//			case ARM_ElfRelocationConstants.R_ARM_GOTRELAX:
//			case ARM_ElfRelocationConstants.R_ARM_GNU_VTENTRY:
//			case ARM_ElfRelocationConstants.R_ARM_GNU_VTINHERIT:
//			case ARM_ElfRelocationConstants.R_ARM_THM_JUMP11:
//			case ARM_ElfRelocationConstants.R_ARM_THM_JUMP8:
//			case ARM_ElfRelocationConstants.R_ARM_TLS_GD32:
//			case ARM_ElfRelocationConstants.R_ARM_TLS_LDM32:
//			case ARM_ElfRelocationConstants.R_ARM_TLS_LDO32:
//			case ARM_ElfRelocationConstants.R_ARM_TLS_IE32:
//			case ARM_ElfRelocationConstants.R_ARM_TLS_LE32:
//			case ARM_ElfRelocationConstants.R_ARM_TLS_LDO12:
//			case ARM_ElfRelocationConstants.R_ARM_TLS_LE12:
//			case ARM_ElfRelocationConstants.R_ARM_TLS_IE12GP:
//			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_0:
//			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_1:
//			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_2:
//			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_3:
//			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_4:
//			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_5:
//			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_6:
//			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_7:
//			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_8:
//			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_9:
//			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_10:
//			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_11:
//			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_12:
//			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_13:
//			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_14:
//			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_15:
//			case ARM_ElfRelocationConstants.R_ARM_THM_TLS_DESCSEQ16:
//			case ARM_ElfRelocationConstants.R_ARM_THM_TLS_DESCSEQ32:
//				return false;
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
		return (processor.equals(Processor.findOrPossiblyCreateProcessor("ARM")));
	}

}
