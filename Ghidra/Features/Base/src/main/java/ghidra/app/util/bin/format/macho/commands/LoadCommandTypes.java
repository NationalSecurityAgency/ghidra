/* ###
 * IP: GHIDRA
 * NOTE: crypt info here is OK because we don't actually decrypt; only mark the section as encrypted and move on
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
package ghidra.app.util.bin.format.macho.commands;

import java.lang.reflect.Field;

/**
 * {@link LoadCommand} types 
 */
public final class LoadCommandTypes {

	//@formatter:off
	/**
	 * After MacOS X 10.1 when a new load command is added that is required to be
	 * understood by the dynamic linker for the image to execute properly the
	 * LC_REQ_DYLD bit will be or'ed into the load command constant.  If the dynamic
	 * linker sees such a load command that it does not understand, it will issue a
	 * "unknown load command required for execution" error and refuse to use the
	 * image.  Other load commands without this bit that are not understood will
	 * simply be ignored.
	 */
	public final static int LC_REQ_DYLD = 0x80000000;

	/** segment of this file to be mapped */
	public final static int LC_SEGMENT                = 0x1;
	
	/** link-edit stab symbol table info */
	public final static int LC_SYMTAB                 = 0x2;
	
	/** link-edit gdb symbol table info (obsolete) */
	public final static int LC_SYMSEG                 = 0x3;
	
	/** thread */
	public final static int LC_THREAD                 = 0x4;
	
	/** unix thread (includes a stack) */
	public final static int LC_UNIXTHREAD             = 0x5;
	
	/** load a specified fixed VM shared library */
	public final static int LC_LOADFVMLIB             = 0x6;
	
	/** fixed VM shared library identification */
	public final static int LC_IDFVMLIB               = 0x7;
	
	/** object identification info (obsolete) */
	public final static int LC_IDENT                  = 0x8;
	
	/** fixed VM file inclusion (internal use) */
	public final static int LC_FVMFILE                = 0x9;
	
	/** prepage command (internal use) */
	public final static int LC_PREPAGE                = 0xa;
	
	/** dynamic link-edit symbol table info */
	public final static int LC_DYSYMTAB               = 0xb;
	
	/** load a dynamically linked shared library */
	public final static int LC_LOAD_DYLIB             = 0xc;
	
	/** dynamically linked shared lib ident */
	public final static int LC_ID_DYLIB               = 0xd;
	
	/** load a dynamic linker */
	public final static int LC_LOAD_DYLINKER          = 0xe;
	
	/** dynamic linker identification */
	public final static int LC_ID_DYLINKER            = 0xf;
	
	/** modules prebound for a dynamically linked shared library */
	public final static int LC_PREBOUND_DYLIB         = 0x10;
	
	/** image routines */
	public final static int LC_ROUTINES               = 0x11;
	
	/** sub framework */
	public final static int LC_SUB_FRAMEWORK          = 0x12;
	
	/** sub umbrella */
	public final static int LC_SUB_UMBRELLA           = 0x13;
	
	/** sub client */
	public final static int LC_SUB_CLIENT             = 0x14;
	
	/** sub library */
    public final static int LC_SUB_LIBRARY            = 0x15;
    
	/** two-level namespace lookup hints */
	public final static int LC_TWOLEVEL_HINTS         = 0x16;
	
	/** prebind checksum */
	public final static int LC_PREBIND_CKSUM          = 0x17;
	
	/** load a dynamically linked shared library that is allowed to be missing (all symbols are weak imported) */
	public final static int LC_LOAD_WEAK_DYLIB        = 0x18 | LC_REQ_DYLD;
	
	/** 64-bit segment of this file to be mapped */
	public final static int LC_SEGMENT_64             = 0x19;
	
	/** 64-bit image routines */
	public final static int LC_ROUTINES_64            = 0x1a;
	
	/** specifies the 128 bit UUID for an image */
	public final static int LC_UUID                   = 0x1b;
	
	/** Run path additions */
	public final static int LC_RPATH                  = 0x1c | LC_REQ_DYLD;
	
	/** local of code signature */
	public final static int LC_CODE_SIGNATURE         = 0x1d;
	
	/** local of info to split segments */
	public final static int LC_SEGMENT_SPLIT_INFO     = 0x1e;
	
	/** load and re-export dylib */
	public final static int LC_REEXPORT_DYLIB         = 0x1f | LC_REQ_DYLD;
	
	/** Delay load of dylib until first use */
	public final static int LC_LAZY_LOAD_DYLIB        = 0x20;
	
	/** encrypted segment information */
	public final static int LC_ENCRYPTION_INFO        = 0x21;
	
	/** compressed dyld information */
	public final static int LC_DYLD_INFO              = 0x22;
	
	/** compressed dyld information only */
	public final static int LC_DYLD_INFO_ONLY         = 0x22 | LC_REQ_DYLD;
	
	/** Load upward dylib */
	public final static int LC_LOAD_UPWARD_DYLIB      = 0x23 | LC_REQ_DYLD;
	
	/** Build for MacOSX min OS version */
	public final static int LC_VERSION_MIN_MACOSX     = 0x24;
	
	/** Build for iPhoneOS min OS version */
	public final static int LC_VERSION_MIN_IPHONEOS   = 0x25;
	
	/** Compressed table of function start addresses */
	public final static int LC_FUNCTION_STARTS        = 0x26;
	
	/** String for DYLD to treat environment variable */
	public final static int LC_DYLD_ENVIRONMENT       = 0x27;
	
	/** Replacement for LC_UNIXTHREAD */
	public final static int LC_MAIN                   = 0x28 | LC_REQ_DYLD;
	
	/** Table of non-instructions in __text */
	public final static int LC_DATA_IN_CODE           = 0x29;
	
	/** Source version used to build binary */
	public final static int LC_SOURCE_VERSION         = 0x2a;
	
	/** Code signing DRs copied from linked dylibs */
	public final static int LC_DYLIB_CODE_SIGN_DRS    = 0x2b;
	
	/** 64-bit encrypted segment information */
	public final static int LC_ENCRYPTION_INFO_64     = 0x2c;
	
	/** Linker options in MH_OBJECT files */
	public final static int LC_LINKER_OPTIONS         = 0x2d;
	
	/** Optimization hints in MH_OBJECT files */
	public final static int LC_OPTIMIZATION_HINT      = 0x2e;
	
	/** Build for AppleTV min OS version */
	public final static int LC_VERSION_MIN_TVOS       = 0x2f;
	
	/** Build for Watch min OS version */
	public final static int LC_VERSION_MIN_WATCHOS    = 0x30;
	
	/** Arbitrary data included within a Mach-O file */
	public final static int LC_NOTE                   = 0x31;
	
	/** Build for platform min OS version */
	public final static int LC_BUILD_VERSION          = 0x32;
	
	/** Used with linkedit_data_command, payload is trie **/
	public final static int LC_DYLD_EXPORTS_TRIE      = 0x33 | LC_REQ_DYLD;
	
	/** Used with linkedit_data_command **/
	public final static int LC_DYLD_CHAINED_FIXUPS    = 0x34 | LC_REQ_DYLD;
	
	/** Used with fileset_entry_command **/
	public final static int LC_FILESET_ENTRY          = 0x35 | LC_REQ_DYLD;
	//@formatter:on

	/**
	 * Gets the name of the given load command type
	 * 
	 * @param type The load command type
	 * @return The name of the given load command type
	 */
	public final static String getLoadCommandName(int type) {
		for (Field field : LoadCommandTypes.class.getDeclaredFields()) {
			if (!field.getName().startsWith("LC_")) {
				continue;
			}
			try {
				Integer value = (Integer) field.get(null);
				if (type == value) {
					return field.getName();
				}
			}
			catch (Exception e) {
				break;
			}
		}
		return "LC_UNKNOWN_%X".formatted(type);
	}
}
