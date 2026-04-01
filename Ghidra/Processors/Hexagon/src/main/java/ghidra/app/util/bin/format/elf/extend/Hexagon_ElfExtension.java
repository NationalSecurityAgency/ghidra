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
import ghidra.app.util.bin.format.elf.ElfDynamicType.ElfDynamicValueType;
import ghidra.program.model.lang.Language;

public class Hexagon_ElfExtension extends ElfExtension {

	// Elf Program Header Extensions
	public static final ElfProgramHeaderType PT_ARM_EXIDX =
		new ElfProgramHeaderType(0x70000000, "PT_ARM_EXIDX", "Frame unwind information");

	// Elf Section Header Extensions
	public static final ElfSectionHeaderType SHT_ARM_EXIDX =
		new ElfSectionHeaderType(0x70000001, "SHT_ARM_EXIDX", "Exception Index table");
	public static final ElfSectionHeaderType SHT_ARM_PREEMPTMAP = new ElfSectionHeaderType(
		0x70000002, "SHT_ARM_PREEMPTMAP", "BPABI DLL dynamic linking preemption map");
	public static final ElfSectionHeaderType SHT_ARM_ATTRIBUTES = new ElfSectionHeaderType(
		0x70000003, "SHT_ARM_ATTRIBUTES", "Object file compatibility attributes");
	public static final ElfSectionHeaderType SHT_ARM_DEBUGOVERLAY =
		new ElfSectionHeaderType(0x70000004, "SHT_ARM_DEBUGOVERLAY", "See DBGOVL for details");
	public static final ElfSectionHeaderType SHT_ARM_OVERLAYSECTION =
		new ElfSectionHeaderType(0x70000005, "SHT_ARM_OVERLAYSECTION",
			"See Debugging Overlaid Programs (DBGOVL) for details");

	// Elf Dynamic Type Extensions

	// DT_HEXAGON_SYMSZ: This value is equivalent to the value of DT_SYMENT multiplied by the value 
	// field "nchain" in the hash table pointed to by DT_HASH.
	public static final ElfDynamicType DT_HEXAGON_SYMSZ =
		new ElfDynamicType(0x70000000, "DT_HEXAGON_SYMSZ",
			"Size in bytes of the DT_SYMTAB symbol table ", ElfDynamicValueType.VALUE);

	// DT_HEXAGON_VER: Currently can be a value of 2 or 3.  Hexagon ABI requires a value of 3
	// although the default is 2.
	public static final ElfDynamicType DT_HEXAGON_VER = new ElfDynamicType(0x70000001,
		"DT_HEXAGON_VER", "Version of interface with dynamic linker", ElfDynamicValueType.VALUE);

	public static final ElfDynamicType DT_HEXAGON_PLT = new ElfDynamicType(0x70000002,
		"DT_HEXAGON_PLT", "Image offset of the PLT", ElfDynamicValueType.VALUE);

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_HEXAGON;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		return canHandle(elfLoadHelper.getElfHeader()) &&
			"Hexagon".equals(language.getProcessor().toString());
	}

	@Override
	public String getDataTypeSuffix() {
		return "_Hexagon";
	}

}
