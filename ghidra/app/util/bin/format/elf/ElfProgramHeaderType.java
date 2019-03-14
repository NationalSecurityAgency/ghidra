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
package ghidra.app.util.bin.format.elf;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.EnumDataType;
import ghidra.util.StringUtilities;
import ghidra.util.exception.DuplicateNameException;

public class ElfProgramHeaderType {

	private static Map<Integer, ElfProgramHeaderType> defaultElfProgramHeaderTypeMap =
		new HashMap<Integer, ElfProgramHeaderType>();

	public static ElfProgramHeaderType PT_NULL = addDefaultProgramHeaderType(
		ElfProgramHeaderConstants.PT_NULL, "PT_NULL", "Unused/Undefined segment");
	public static ElfProgramHeaderType PT_LOAD = addDefaultProgramHeaderType(
		ElfProgramHeaderConstants.PT_LOAD, "PT_LOAD", "Loadable segment");
	public static ElfProgramHeaderType PT_DYNAMIC = addDefaultProgramHeaderType(
		ElfProgramHeaderConstants.PT_DYNAMIC, "PT_DYNAMIC", "Dynamic linking information");
	public static ElfProgramHeaderType PT_INTERP = addDefaultProgramHeaderType(
		ElfProgramHeaderConstants.PT_INTERP, "PT_INTERP", "Interpreter path name");
	public static ElfProgramHeaderType PT_NOTE = addDefaultProgramHeaderType(
		ElfProgramHeaderConstants.PT_NOTE, "PT_NOTE", "Auxiliary information location");
	public static ElfProgramHeaderType PT_SHLIB =
		addDefaultProgramHeaderType(ElfProgramHeaderConstants.PT_SHLIB, "PT_SHLIB", "");
	public static ElfProgramHeaderType PT_PHDR = addDefaultProgramHeaderType(
		ElfProgramHeaderConstants.PT_PHDR, "PT_PHDR", "Program header table");
	public static ElfProgramHeaderType PT_TLS = addDefaultProgramHeaderType(
		ElfProgramHeaderConstants.PT_TLS, "PT_TLS", "Thread-Local Storage template");

	// OS-specific range: 0x60000000 - 0x6fffffff

	public static ElfProgramHeaderType PT_GNU_EH_FRAME = addDefaultProgramHeaderType(
		ElfProgramHeaderConstants.PT_GNU_EH_FRAME, "PT_GNU_EH_FRAME", "GCC .eh_frame_hdr segment");
	public static ElfProgramHeaderType PT_GNU_STACK = addDefaultProgramHeaderType(
		ElfProgramHeaderConstants.PT_GNU_STACK, "PT_GNU_STACK", "Indicates stack executability");
	public static ElfProgramHeaderType PT_GNU_RELRO = addDefaultProgramHeaderType(
			ElfProgramHeaderConstants.PT_GNU_RELRO, "PT_GNU_RELRO", "Specifies segments which may be read-only post-relocation");

	// Processor-specific range: 0x70000000 - 0x7fffffff

	private static ElfProgramHeaderType addDefaultProgramHeaderType(int value, String name,
			String description) {
		try {
			ElfProgramHeaderType type = new ElfProgramHeaderType(value, name, description);
			addProgramHeaderType(type, defaultElfProgramHeaderTypeMap);
			return type;
		}
		catch (DuplicateNameException e) {
			throw new RuntimeException("ElfProgramHeaderType initialization error", e);
		}
	}

	/**
	 * Add the specified program header type to the specified map.
	 * @param type program header type
	 * @param programHeaderTypeMap
	 * @throws DuplicateNameException if new type name already defined within
	 * the specified map
	 */
	public static void addProgramHeaderType(ElfProgramHeaderType type,
			Map<Integer, ElfProgramHeaderType> programHeaderTypeMap)
					throws DuplicateNameException {
		ElfProgramHeaderType conflictType = programHeaderTypeMap.get(type.value);
		if (conflictType != null) {
			throw new DuplicateNameException(
				"ElfProgramHeaderType conflict during initialization (" + type.name + " / " +
					conflictType.name + "), value=0x" +
					Integer.toHexString(type.value));
		}
		for (ElfProgramHeaderType existingType : programHeaderTypeMap.values()) {
			if (type.name.equalsIgnoreCase(existingType.name)) {
				throw new DuplicateNameException(
					"ElfProgramHeaderType conflict during initialization, name=" + type.name);
			}
		}
		programHeaderTypeMap.put(type.value, type);
	}

	public final int value;
	public final String name;
	public final String description;

	public ElfProgramHeaderType(int value, String name, String description) {
		if (value < 0) {
			throw new IllegalArgumentException(
				"ElfProgramHeaderType value out of range: 0x" + Long.toHexString(value));
		}
		this.value = value;
		this.name = name;
		this.description = description;
	}

	public static void addDefaultTypes(Map<Integer, ElfProgramHeaderType> programHeaderTypeMap) {
		programHeaderTypeMap.putAll(defaultElfProgramHeaderTypeMap);
	}

	public static EnumDataType getEnumDataType(boolean is32bit, String typeSuffix,
			Map<Integer, ElfProgramHeaderType> dynamicTypeMap) {
		int size = is32bit ? 4 : 8;
		String name = is32bit ? "Elf32_PHType" : "Elf64_PHType";
		if (typeSuffix != null) {
			name = name + typeSuffix;
		}
		EnumDataType phTypeEnum = new EnumDataType(new CategoryPath("/ELF"), name, size);
		for (ElfProgramHeaderType type : dynamicTypeMap.values()) {
			phTypeEnum.add(type.name, type.value);
		}
		return phTypeEnum;
	}

	@Override
	public String toString() {
		return name + "(0x" + StringUtilities.pad(Integer.toHexString(value), '0', 8) + ")";
	}

}
