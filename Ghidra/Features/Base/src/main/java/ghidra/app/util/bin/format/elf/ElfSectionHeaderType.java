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

public class ElfSectionHeaderType {

	private static Map<Integer, ElfSectionHeaderType> defaultElfSectionHeaderTypeMap =
		new HashMap<Integer, ElfSectionHeaderType>();

	public static ElfSectionHeaderType SHT_NULL = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_NULL, "SHT_NULL", "Inactive section header");
	public static ElfSectionHeaderType SHT_PROGBITS = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_PROGBITS, "SHT_PROGBITS", "Program defined section");
	public static ElfSectionHeaderType SHT_SYMTAB =
		addDefaultSectionHeaderType(ElfSectionHeaderConstants.SHT_SYMTAB, "SHT_SYMTAB",
			"Symbol table for link editing and dynamic linking");
	public static ElfSectionHeaderType SHT_STRTAB = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_STRTAB, "SHT_STRTAB", "String table");
	public static ElfSectionHeaderType SHT_RELA = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_RELA, "SHT_RELA", "Relocation entries with explicit addends");
	public static ElfSectionHeaderType SHT_HASH = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_HASH, "SHT_HASH", "Symbol hash table for dynamic linking");
	public static ElfSectionHeaderType SHT_DYNAMIC = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_DYNAMIC, "SHT_DYNAMIC", "Dynamic linking information");
	public static ElfSectionHeaderType SHT_NOTE =
		addDefaultSectionHeaderType(ElfSectionHeaderConstants.SHT_NOTE, "SHT_NOTE",
			"Section holds information that marks the file");
	public static ElfSectionHeaderType SHT_NOBITS = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_NOBITS, "SHT_NOBITS", "Section contains no bytes");
	public static ElfSectionHeaderType SHT_REL = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_REL, "SHT_REL", "Relocation entries w/o explicit addends");
	public static ElfSectionHeaderType SHT_SHLIB =
		addDefaultSectionHeaderType(ElfSectionHeaderConstants.SHT_SHLIB, "SHT_SHLIB", "");
	public static ElfSectionHeaderType SHT_DYNSYM = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_DYNSYM, "SHT_DYNSYM", "Symbol table for dynamic linking");
	public static ElfSectionHeaderType SHT_INIT_ARRAY =
		addDefaultSectionHeaderType(ElfSectionHeaderConstants.SHT_INIT_ARRAY, "SHT_INIT_ARRAY",
			"Array of initializer functions");
	public static ElfSectionHeaderType SHT_FINI_ARRAY = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_FINI_ARRAY, "SHT_FINI_ARRAY", "Array of finalizer functions");
	public static ElfSectionHeaderType SHT_PREINIT_ARRAY =
		addDefaultSectionHeaderType(ElfSectionHeaderConstants.SHT_PREINIT_ARRAY,
			"SHT_PREINIT_ARRAY", "Array of pre-initializer functions");
	public static ElfSectionHeaderType SHT_GROUP = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_GROUP, "SHT_GROUP", "Section group");
	public static ElfSectionHeaderType SHT_SYMTAB_SHNDX = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_SYMTAB_SHNDX, "SHT_SYMTAB_SHNDX", "Extended section indeces");

	// OS-specific range: 0x60000000 - 0x6fffffff
	
	public static ElfSectionHeaderType SHT_ANDROID_REL = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_ANDROID_REL, "SHT_ANDROID_REL", "Android relocation entries w/o explicit addends");
	public static ElfSectionHeaderType SHT_ANDROID_RELA = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_ANDROID_RELA, "SHT_ANDROID_RELA", "Android relocation entries with explicit addends");

	public static ElfSectionHeaderType SHT_GNU_ATTRIBUTES = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_GNU_ATTRIBUTES, "SHT_GNU_ATTRIBUTES", "Object attributes");
	public static ElfSectionHeaderType SHT_GNU_HASH = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_GNU_HASH, "SHT_GNU_HASH", "GNU-style hash table");
	public static ElfSectionHeaderType SHT_GNU_LIBLIST = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_GNU_LIBLIST, "SHT_GNU_LIBLIST", "Prelink library list");
	public static ElfSectionHeaderType SHT_CHECKSUM = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_CHECKSUM, "SHT_CHECKSUM", "Checksum for DSO content");

	public static ElfSectionHeaderType SHT_SUNW_move =
		addDefaultSectionHeaderType(ElfSectionHeaderConstants.SHT_SUNW_move, "SHT_SUNW_move", "");
	public static ElfSectionHeaderType SHT_SUNW_COMDAT = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_SUNW_COMDAT, "SHT_SUNW_COMDAT", "");
	public static ElfSectionHeaderType SHT_SUNW_syminfo = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_SUNW_syminfo, "SHT_SUNW_syminfo", "");
	public static ElfSectionHeaderType SHT_GNU_verdef = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_GNU_verdef, "SHT_GNU_verdef", "Version definition section");
	public static ElfSectionHeaderType SHT_GNU_verneed = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_GNU_verneed, "SHT_GNU_verneed", "Version needs section");
	public static ElfSectionHeaderType SHT_GNU_versym = addDefaultSectionHeaderType(
		ElfSectionHeaderConstants.SHT_GNU_versym, "SHT_GNU_versym", "Version symbol table");

	// Processor-specific range: 0x70000000 - 0x7fffffff

	private static ElfSectionHeaderType addDefaultSectionHeaderType(int value, String name,
			String description) {
		try {
			ElfSectionHeaderType type = new ElfSectionHeaderType(value, name, description);
			addSectionHeaderType(type, defaultElfSectionHeaderTypeMap);
			return type;
		}
		catch (DuplicateNameException e) {
			throw new RuntimeException("ElfSectionHeaderType initialization error", e);
		}
	}

	/**
	 * Add the specified section header type to the specified map.
	 * @param type section header type
	 * @param sectionHeaderTypeMap
	 * @throws DuplicateNameException if new type name already defined within
	 * the specified map
	 */
	public static void addSectionHeaderType(ElfSectionHeaderType type,
			Map<Integer, ElfSectionHeaderType> sectionHeaderTypeMap) throws DuplicateNameException {
		ElfSectionHeaderType conflictType = sectionHeaderTypeMap.get(type.value);
		if (conflictType != null) {
			throw new DuplicateNameException(
				"ElfSectionHeaderType conflict during initialization (" + type.name + " / " +
					conflictType.name + "), value=0x" + Integer.toHexString(type.value));
		}
		for (ElfSectionHeaderType existingType : sectionHeaderTypeMap.values()) {
			if (type.name.equalsIgnoreCase(existingType.name)) {
				throw new DuplicateNameException(
					"ElfSectionHeaderType conflict during initialization, name=" + type.name);
			}
		}
		sectionHeaderTypeMap.put(type.value, type);
	}

	public final int value;
	public final String name;
	public final String description;

	public ElfSectionHeaderType(int value, String name, String description) {
		this.value = value;
		this.name = name;
		this.description = description;
	}

	public static void addDefaultTypes(Map<Integer, ElfSectionHeaderType> programHeaderTypeMap) {
		programHeaderTypeMap.putAll(defaultElfSectionHeaderTypeMap);
	}

	public static EnumDataType getEnumDataType(boolean is32bit, String typeSuffix,
			Map<Integer, ElfSectionHeaderType> dynamicTypeMap) {
		int size = is32bit ? 4 : 8;
		String name = is32bit ? "Elf32_PHType" : "Elf64_PHType";
		if (typeSuffix != null) {
			name = name + typeSuffix;
		}
		EnumDataType phTypeEnum = new EnumDataType(new CategoryPath("/ELF"), name, size);
		for (ElfSectionHeaderType type : dynamicTypeMap.values()) {
			phTypeEnum.add(type.name, type.value);
		}
		return phTypeEnum;
	}

	@Override
	public String toString() {
		return name + "(0x" + StringUtilities.pad(Integer.toHexString(value), '0', 8) + ")";
	}

}
