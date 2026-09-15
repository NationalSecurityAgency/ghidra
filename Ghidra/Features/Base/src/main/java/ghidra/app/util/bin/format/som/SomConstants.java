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
package ghidra.app.util.bin.format.som;

/**
 * SOM constant values
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomConstants {

	// System IDs
	public static final int SYSTEM_PA_RISC_1_0 = 0x20b;
	public static final int SYSTEM_PA_RISC_1_1 = 0x210;
	public static final int SYSTEM_PA_RISC_2_0 = 0x214;

	// Magic numbers
	public static final int MAGIC_LIBRARY = 0x104;
	public static final int MAGIC_RELOCATABLE = 0x106;
	public static final int MAGIC_NON_SHAREABLE_EXE = 0x107;
	public static final int MAGIC_SHAREABLE_EXE = 0x108;
	public static final int MAGIC_SHARABLE_DEMAND_LOADABLE_EXE = 0x10b;
	public static final int MAGIC_DYNAMIC_LOAD_LIBRARY = 0x10d;
	public static final int MAGIC_SHARED_LIBRARY = 0x10e;
	public static final int MAGIC_RELOCATABLE_LIBRARY = 0x0619;

	// Version IDs
	public static final int VERSION_OLD = 0x85082112;
	public static final int VERSION_NEW = 0x87102412;

	// Auxiliary header types
	public static final int TYPE_NULL = 0;
	public static final int LINKER_FOOTPRINT = 1;
	public static final int MEP_IX_PROGRAM = 2;
	public static final int DEBUGGER_FOOTPRINT = 3;
	public static final int EXEC_AUXILIARY_HEADER = 4;
	public static final int IPL_AUXILIARY_HEADER = 5;
	public static final int VERSION_STRIING = 6;
	public static final int MPE_IX_PROGRAM = 7;
	public static final int MPE_IX_SOM = 8;
	public static final int COPYRIGHT = 9;
	public static final int SHARED_LIBARY_VERSION_INFORMATION = 10;
	public static final int PRODUCT_SPECIFICS = 11;
	public static final int NETWARE_LOADABLE_MODULE = 12;

	// Symbol types
	public static final int SYMBOL_NULL = 0;
	public static final int SYMBOL_ABSOLUTE = 1;
	public static final int SYMBOL_DATA = 2;
	public static final int SYMBOL_CODE = 3;
	public static final int SYMBOL_PRI_PROG = 4;
	public static final int SYMBOL_SEC_PROG = 5;
	public static final int SYMBOL_ENTRY = 6;
	public static final int SYMBOL_STORAGE = 7;
	public static final int SYMBOL_STUB = 8;
	public static final int SYMBOL_MODULE = 9;
	public static final int SYMBOL_SYM_EXT = 10;
	public static final int SYMBOL_ARG_EXT = 11;
	public static final int SYMBOL_MILLICODE = 12;
	public static final int SYMBOL_PLABEL = 13;
	public static final int SYMBOL_OCT_DIS = 14;
	public static final int SYMBOL_MILLI_EXT = 15;
	public static final int SYMBOL_TSTORAGE = 16;
	public static final int SYMBOL_COMDAT = 17;

	// Symbol scopes
	public static final int SYMBOL_SCOPE_UNSAT = 0;
	public static final int SYMBOL_SCOPE_EXTERNAL = 1;
	public static final int SYMBOL_SCOPE_LOCAL = 2;
	public static final int SYMBOL_SCOPE_UNIVERSAL = 3;

	// Dynamic relocation types
	public static final int DR_PLABEL_EXT = 1;
	public static final int DR_PLABEL_INT = 2;
	public static final int DR_DATA_EXT = 3;
	public static final int DR_DATA_INT = 4;
	public static final int DR_PROPAGATE = 5;
	public static final int DR_INVOKE = 6;
	public static final int DR_TEXT_INT = 7;
}
