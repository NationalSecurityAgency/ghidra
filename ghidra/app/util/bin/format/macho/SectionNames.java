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
package ghidra.app.util.bin.format.macho;

public final class SectionNames {

	/** the real text part of the text section no headers, and no padding */
	public final static String TEXT                 = "__text";
	/** Constant null-terminated C strings */
	public final static String TEXT_CSTRING         = "__cstring";
	/** Position-independent indirect symbol stubs */
	public final static String TEXT_PICSYMBOL_STUB  = "__picsymbol_stub";
	/** Indirect symbol stubs */
	public final static String TEXT_SYMBOL_STUB     = "__symbol_stub";
	/** Initialized constant variables */
	public final static String TEXT_CONST           = "__const";
	/** 4-byte literal values. single-precision floating pointer constants */
	public final static String TEXT_LITERAL4        = "__literal4";
	/** 8-byte literal values. double-precision floating pointer constants */
	public final static String TEXT_LITERAL8        = "__literal8";
	/** the fvmlib initialization section */
	public final static String TEXT_FVMLIB_INIT0    = "__fvmlib_init0";
	/** the section following the fvmlib initialization section */
	public final static String TEXT_FVMLIB_INIT1    = "__fvmlib_init1";

	/** the real initialized data section no padding, no bss overlap */
	public final static String DATA                 = "__data";
	/** Lazy symbol pointers, which are indirect references to imported functions */
	public final static String DATA_LA_SYMBOL_PTR   = "__la_symbol_ptr";
	/** Non-lazy symbol pointers, which are indirect references to imported functions */
	public final static String DATA_NL_SYMBOL_PTR   = "__nl_symbol_ptr";
	/** Place holder section used by dynamic linker */
	public final static String DATA_DYLD            = "__dyld";
	/** Initialized relocatable constant variables */
	public final static String DATA_CONST           = "__const";
	/** Module initialization functions. C++ places static constructors here. */
	public final static String DATA_MOD_INIT_FUNC   = "__mod_init_func";
	/** Module termination functions */
	public final static String DATA_MOD_TERM_FUNC   = "__mod_term_func";
	/** the real uninitialized data section no padding */
	public final static String SECT_BSS             = "__bss";
	/** the section common symbols are allocated in by the link editor */
	public final static String SECT_COMMON          = "__common";
	
	/** global offset table section **/
	public final static String SECT_GOT				= "__got";

	/** symbol table */
	public final static String OBJC_SYMBOLS         = "__symbol_table";
	/** module information */
	public final static String OBJC_MODULES         = "__module_info";
	/** string table */
	public final static String OBJC_STRINGS         = "__selector_strs";
	/** string table */
	public final static String OBJC_REFS            = "__selector_refs";

	/** Stubs for calls to functions in a dynamic library */
	public final static String IMPORT_JUMP_TABLE    = "__jump_table";
	/** Non-lazy symbol pointers */
	public final static String IMPORT_POINTERS      = "__pointers";
	/** Section dedicated to holding global program variables */
	public final static String PROGRAM_VARS         = "__program_vars";
}
