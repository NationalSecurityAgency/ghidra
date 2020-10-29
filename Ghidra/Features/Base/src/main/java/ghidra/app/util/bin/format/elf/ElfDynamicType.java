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

import ghidra.util.Msg;
import ghidra.util.StringUtilities;
import ghidra.util.exception.DuplicateNameException;

public class ElfDynamicType {

	public enum ElfDynamicValueType {
		VALUE, ADDRESS, STRING
	}

	private static Map<Integer, ElfDynamicType> defaultElfDynamicTypeMap =
		new HashMap<Integer, ElfDynamicType>();

	public static ElfDynamicType DT_NULL = addDefaultDynamicType(0, "DT_NULL",
		"Marks end of dynamic section", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_NEEDED =
		addDefaultDynamicType(1, "DT_NEEDED", "Name of needed library", ElfDynamicValueType.STRING);
	public static ElfDynamicType DT_PLTRELSZ = addDefaultDynamicType(2, "DT_PLTRELSZ",
		"Size in bytes of PLT relocs", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_PLTGOT = addDefaultDynamicType(3, "DT_PLTGOT",
		"Processor defined value", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_HASH = addDefaultDynamicType(4, "DT_HASH",
		"Address of symbol hash table", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_STRTAB = addDefaultDynamicType(5, "DT_STRTAB",
		"Address of string table", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_SYMTAB = addDefaultDynamicType(6, "DT_SYMTAB",
		"Address of symbol table", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_RELA =
		addDefaultDynamicType(7, "DT_RELA", "Address of Rela relocs", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_RELASZ = addDefaultDynamicType(8, "DT_RELASZ",
		"Total size of Rela relocs", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_RELAENT =
		addDefaultDynamicType(9, "DT_RELAENT", "Size of one Rela reloc", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_STRSZ =
		addDefaultDynamicType(10, "DT_STRSZ", "Size of string table", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_SYMENT = addDefaultDynamicType(11, "DT_SYMENT",
		"Size of one symbol table entry", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_INIT = addDefaultDynamicType(12, "DT_INIT",
		"Address of init function", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_FINI = addDefaultDynamicType(13, "DT_FINI",
		"Address of termination function", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_SONAME = addDefaultDynamicType(14, "DT_SONAME",
		"Name of shared object (string ref)", ElfDynamicValueType.STRING);
	public static ElfDynamicType DT_RPATH =
		addDefaultDynamicType(15, "DT_RPATH", "Library search path", ElfDynamicValueType.STRING);
	public static ElfDynamicType DT_SYMBOLIC = addDefaultDynamicType(16, "DT_SYMBOLIC",
		"Start symbol search here", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_REL =
		addDefaultDynamicType(17, "DT_REL", "Address of Rel relocs", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_RELSZ = addDefaultDynamicType(18, "DT_RELSZ",
		"Total size of Rel relocs", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_RELENT =
		addDefaultDynamicType(19, "DT_RELENT", "Size of one Rel reloc", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_PLTREL =
		addDefaultDynamicType(20, "DT_PLTREL", "Type of reloc in PLT", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_DEBUG = addDefaultDynamicType(21, "DT_DEBUG",
		"For debugging (unspecified)", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_TEXTREL = addDefaultDynamicType(22, "DT_TEXTREL",
		"Reloc might modify .text", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_JMPREL = addDefaultDynamicType(23, "DT_JMPREL",
		"Address of PLT relocs", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_BIND_NOW = addDefaultDynamicType(24, "DT_BIND_NOW",
		"Process relocations of object", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_INIT_ARRAY = addDefaultDynamicType(25, "DT_INIT_ARRAY",
		"Address of array with addresses of init fct", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_FINI_ARRAY = addDefaultDynamicType(26, "DT_FINI_ARRAY",
		"Address of array with addresses of fini fct", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_INIT_ARRAYSZ = addDefaultDynamicType(27, "DT_INIT_ARRAYSZ",
		"Size in bytes of DT_INIT_ARRAY", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_FINI_ARRAYSZ = addDefaultDynamicType(28, "DT_FINI_ARRAYSZ",
		"Size in bytes of DT_FINI_ARRAY", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_RUNPATH = addDefaultDynamicType(29, "DT_RUNPATH",
		"Library search path (string ref)", ElfDynamicValueType.STRING);
	// see DF_ constants for flag definitions
	public static ElfDynamicType DT_FLAGS = addDefaultDynamicType(30, "DT_FLAGS",
		"Flags for the object being loaded", ElfDynamicValueType.VALUE);

	// Experimental RELR relocation support
	// - see proposal at https://groups.google.com/forum/#!topic/generic-abi/bX460iggiKg
	public static ElfDynamicType DT_RELRSZ = addDefaultDynamicType(35, "DT_RELRSZ",
		"Total size of Relr relocs", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_RELR =
		addDefaultDynamicType(36, "DT_RELR", "Address of Relr relocs", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_RELRENT = addDefaultDynamicType(37, "DT_RELRENT",
		"Size of Relr relocation entry", ElfDynamicValueType.VALUE);

	public static final int DF_ORIGIN = 0x1; 		// $ORIGIN processing required
	public static final int DF_SYMBOLIC = 0x2;		// Symbolic symbol resolution required
	public static final int DF_TEXTREL = 0x4;		// Text relocations exist
	public static final int DF_BIND_NOW = 0x8;		// Non-lazy binding required
	public static final int DF_STATIC_TLS = 0x10;	// Object uses static TLS scheme

	// glibc and BSD disagree for DT_ENCODING
	//  public static ElfDynamicType DT_ENCODING = addDefaultDynamicType(32, "DT_ENCODING",
	//	  "Start of encoded range", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_PREINIT_ARRAY = addDefaultDynamicType(32, "DT_PREINIT_ARRAY",
		"Array with addresses of preinit fct", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_PREINIT_ARRAYSZ = addDefaultDynamicType(33,
		"DT_PREINIT_ARRAYSZ", "Size in bytes of DT_PREINIT_ARRAY", ElfDynamicValueType.VALUE);

	// OS-specific range: 0x6000000d - 0x6ffff000

	public static ElfDynamicType DT_ANDROID_REL = addDefaultDynamicType(0x6000000F,
		"DT_ANDROID_REL", "Address of Rel relocs", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_ANDROID_RELSZ = addDefaultDynamicType(0x60000010,
		"DT_ANDROID_RELSZ", "Total size of Rel relocs", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_ANDROID_RELA = addDefaultDynamicType(0x60000011,
		"DT_ANDROID_RELA", "Address of Rela relocs", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_ANDROID_RELASZ = addDefaultDynamicType(0x60000012,
		"DT_ANDROID_RELASZ", "Total size of Rela relocs", ElfDynamicValueType.VALUE);

	public static ElfDynamicType DT_ANDROID_RELR = addDefaultDynamicType(0x6FFFE000,
		"DT_ANDROID_RELR", "Address of Relr relocs", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_ANDROID_RELRSZ = addDefaultDynamicType(0x6FFFE001,
		"DT_ANDROID_RELRSZ", "Total size of Relr relocs", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_ANDROID_RELRENT = addDefaultDynamicType(0x6FFFE003,
		"DT_ANDROID_RELRENT", "Size of Relr relocation entry", ElfDynamicValueType.VALUE);

	// Value Range (??): 0x6ffffd00 - 0x6ffffdff

	public static ElfDynamicType DT_GNU_PRELINKED = addDefaultDynamicType(0x6ffffdf5,
		"DT_GNU_PRELINKED", "Prelinking timestamp", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_GNU_CONFLICTSZ = addDefaultDynamicType(0x6ffffdf6,
		"DT_GNU_CONFLICTSZ", "Size of conflict section", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_GNU_LIBLISTSZ = addDefaultDynamicType(0x6ffffdf7,
		"DT_GNU_LIBLISTSZ", "Size of library list", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_CHECKSUM =
		addDefaultDynamicType(0x6ffffdf8, "DT_CHECKSUM", "", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_PLTPADSZ =
		addDefaultDynamicType(0x6ffffdf9, "DT_PLTPADSZ", "", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_MOVEENT =
		addDefaultDynamicType(0x6ffffdfa, "DT_MOVEENT", "", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_MOVESZ =
		addDefaultDynamicType(0x6ffffdfb, "DT_MOVESZ", "", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_FEATURE_1 =
		addDefaultDynamicType(0x6ffffdfc, "DT_FEATURE_1", "", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_POSFLAG_1 =
		addDefaultDynamicType(0x6ffffdfd, "DT_POSFLAG_1", "", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_SYMINSZ =
		addDefaultDynamicType(0x6ffffdfe, "DT_SYMINSZ", "", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_SYMINENT =
		addDefaultDynamicType(0x6ffffdff, "DT_SYMINENT", "", ElfDynamicValueType.VALUE);

	// Address Range (??): 0x6ffffe00 - 0x6ffffeff

	public static ElfDynamicType DT_GNU_HASH = addDefaultDynamicType(0x6ffffef5, "DT_GNU_HASH",
		"GNU-style hash table", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_TLSDESC_PLT =
		addDefaultDynamicType(0x6ffffef6, "DT_TLSDESC_PLT", "", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_TLSDESC_GOT =
		addDefaultDynamicType(0x6ffffef7, "DT_TLSDESC_GOT", "", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_GNU_CONFLICT = addDefaultDynamicType(0x6ffffef8,
		"DT_GNU_CONFLICT", "Start of conflict section", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_GNU_LIBLIST = addDefaultDynamicType(0x6ffffef9,
		"DT_GNU_LIBLIST", "Library list", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_CONFIG = addDefaultDynamicType(0x6ffffefa, "DT_CONFIG",
		"Configuration information", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_DEPAUDIT = addDefaultDynamicType(0x6ffffefb, "DT_DEPAUDIT",
		"Dependency auditing", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_AUDIT =
		addDefaultDynamicType(0x6ffffefc, "DT_AUDIT", "Object auditing", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_PLTPAD =
		addDefaultDynamicType(0x6ffffefd, "DT_PLTPAD", "PLT padding", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_MOVETAB =
		addDefaultDynamicType(0x6ffffefe, "DT_MOVETAB", "Move table", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_SYMINFO = addDefaultDynamicType(0x6ffffeff, "DT_SYMINFO",
		"Syminfo table", ElfDynamicValueType.ADDRESS);

	public static ElfDynamicType DT_VERSYM = addDefaultDynamicType(0x6ffffff0, "DT_VERSYM",
		"Address of symbol version table", ElfDynamicValueType.ADDRESS);

	public static ElfDynamicType DT_RELACOUNT =
		addDefaultDynamicType(0x6ffffff9, "DT_RELACOUNT", "", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_RELCOUNT =
		addDefaultDynamicType(0x6ffffffa, "DT_RELCOUNT", "", ElfDynamicValueType.VALUE);

	// see DF_1_ constants for flag definitions
	public static ElfDynamicType DT_FLAGS_1 =
		addDefaultDynamicType(0x6ffffffb, "DT_FLAGS_1", "State flags", ElfDynamicValueType.VALUE);

	public static final int DF_1_NOW = 0x1;
	public static final int DF_1_GLOBAL = 0x2;
	public static final int DF_1_GROUP = 0x4;
	public static final int DF_1_NODELETE = 0x8;
	public static final int DF_1_LOADFLTR = 0x10;
	public static final int DF_1_INITFIRST = 0x20;
	public static final int DF_1_NOOPEN = 0x40;
	public static final int DF_1_ORIGIN = 0x80;
	public static final int DF_1_DIRECT = 0x100;
	public static final int DF_1_INTERPOSE = 0x400;
	public static final int DF_1_NODEFLIB = 0x800;

	public static ElfDynamicType DT_VERDEF = addDefaultDynamicType(0x6ffffffc, "DT_VERDEF",
		"Address of version definition table", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_VERDEFNUM = addDefaultDynamicType(0x6ffffffd, "DT_VERDEFNUM",
		"Number of version definitions", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_VERNEED = addDefaultDynamicType(0x6ffffffe, "DT_VERNEED",
		"Address of table with needed versions", ElfDynamicValueType.ADDRESS);
	public static ElfDynamicType DT_VERNEEDNUM = addDefaultDynamicType(0x6fffffff, "DT_VERNEEDNUM",
		"Number of needed versions", ElfDynamicValueType.VALUE);

	// Processor-specific range: 0x70000000 - 0x7fffffff

	public static ElfDynamicType DT_AUXILIARY = addDefaultDynamicType(0x7ffffffd, "DT_AUXILIARY",
		"Shared object to load before self", ElfDynamicValueType.VALUE);
	public static ElfDynamicType DT_FILTER = addDefaultDynamicType(0x7fffffff, "DT_FILTER",
		"Shared object to get values from", ElfDynamicValueType.VALUE);

	private static ElfDynamicType addDefaultDynamicType(int value, String name, String description,
			ElfDynamicValueType valueType) {
		try {
			ElfDynamicType type = new ElfDynamicType(value, name, description, valueType);
			addDynamicType(type, defaultElfDynamicTypeMap);
			return type;
		}
		catch (DuplicateNameException e) {
			// Make sure error is properly logged during static initialization
			Msg.error(ElfDynamicType.class, "ElfDynamicType initialization error", e);
			throw new RuntimeException(e);
		}
	}

	/**
	 * Add the specified dynamic entry type to the specified map.
	 * @param type dynamic entry type
	 * @param dynamicTypeMap
	 * @throws DuplicateNameException if new type name already defined within
	 * the specified map
	 */
	public static void addDynamicType(ElfDynamicType type,
			Map<Integer, ElfDynamicType> dynamicTypeMap) throws DuplicateNameException {
		ElfDynamicType conflictType = dynamicTypeMap.get(type.value);
		if (conflictType != null) {
			throw new DuplicateNameException(
				"ElfDynamicType conflict during initialization (" + type.name + " / " +
					conflictType.name + "), value=0x" + Integer.toHexString(type.value));
		}
		for (ElfDynamicType existingType : dynamicTypeMap.values()) {
			if (type.name.equalsIgnoreCase(existingType.name)) {
				throw new DuplicateNameException(
					"ElfDynamicType conflict during initialization, name=" + type.name);
			}
		}
		dynamicTypeMap.put(type.value, type);
	}

	public final int value;
	public final String name;
	public final String description;
	public final ElfDynamicValueType valueType;

	public ElfDynamicType(int value, String name, String description,
			ElfDynamicValueType valueType) {
		if (value < 0) {
			throw new IllegalArgumentException(
				"ElfDynamicType value out of range: 0x" + Long.toHexString(value));
		}
		this.value = value;
		this.name = name;
		this.description = description;
		this.valueType = valueType;
	}

	public static void addDefaultTypes(Map<Integer, ElfDynamicType> dynamicTypeMap) {
		dynamicTypeMap.putAll(defaultElfDynamicTypeMap);
	}

	@Override
	public String toString() {
		return name + "(0x" + StringUtilities.pad(Integer.toHexString(value), '0', 8) + ")";
	}
}
