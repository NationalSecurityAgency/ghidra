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
package ghidra.app.util.bin.format.elf.extend;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;

public class AVR8_ElfExtension extends ElfExtension {
	
	// Processor specific flag mask
	public static final int  EF_AVR_MACH = 0x7F;
	
	// bit #7 indicates elf file uses local symbols for relocations
	public static final int  EF_AVR_LINKRELAX_PREPARED = 0x80;
	
	public static final int E_AVR_MACH_AVR1 = 1;
	public static final int E_AVR_MACH_AVR2 = 2;
	public static final int E_AVR_MACH_AVR25 = 25;
	public static final int E_AVR_MACH_AVR3 = 3;
	public static final int E_AVR_MACH_AVR31 = 31;
	public static final int E_AVR_MACH_AVR35 = 35;
	public static final int E_AVR_MACH_AVR4 = 4;
	public static final int E_AVR_MACH_AVR5 = 5;
	public static final int E_AVR_MACH_AVR51 = 51;
	public static final int E_AVR_MACH_AVR6 = 6;
	public static final int E_AVR_MACH_XMEGA1 = 101;
	public static final int E_AVR_MACH_XMEGA2 = 102;
	public static final int E_AVR_MACH_XMEGA3 = 103;
	public static final int E_AVR_MACH_XMEGA4 = 104;
	public static final int E_AVR_MACH_XMEGA5 = 105;
	public static final int E_AVR_MACH_XMEGA6 = 106;
	public static final int E_AVR_MACH_XMEGA7 = 107;

	@Override
	public boolean canHandle(ElfHeader elf) {
		if (elf.e_machine() != ElfConstants.EM_AVR) {
			return false;
		}
		// TODO: limit to specific architectures?
		return true;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		return canHandle(elfLoadHelper.getElfHeader()) &&
			"AVR8".equals(language.getProcessor().toString());
	}

	@Override
	public String getDataTypeSuffix() {
		return "_AVR";
	}

	@Override
	public long getAdjustedMemoryOffset(long elfOffset, AddressSpace space) {
		if ("code".equals(space.getName())) {
			elfOffset >>= 1; // code space modeled with wordsize=2 which differs from ELF model
		}
		return elfOffset;
	}

}
