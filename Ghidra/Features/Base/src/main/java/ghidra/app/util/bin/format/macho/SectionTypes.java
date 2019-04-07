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

import java.lang.reflect.Field;

public final class SectionTypes {

	/** 256 section types */
	public final static int SECTION_TYPE_MASK                       = 0x000000ff;

	/** Type: regular section */
	public final static int S_REGULAR                               = 0x0;
	/** Type: zero fill on demand section */
	public final static int S_ZEROFILL                              = 0x1;
	/** Type: section with only literal C strings*/
	public final static int S_CSTRING_LITERALS                      = 0x2;
	/** Type: section with only 4 byte literals */
	public final static int S_4BYTE_LITERALS                        = 0x3;
	/** Type: section with only 8 byte literals */
	public final static int S_8BYTE_LITERALS                        = 0x4;
	/** Type: section with only pointers to literals */
	public final static int S_LITERAL_POINTERS                      = 0x5;
	/** Type: section with only non-lazy symbol pointers */
	public final static int S_NON_LAZY_SYMBOL_POINTERS              = 0x6;
	/** Type: section with only lazy symbol pointers */
	public final static int S_LAZY_SYMBOL_POINTERS                  = 0x7;
	/** Type: section with only symbol stubs, byte size of stub in the reserved2 field */
	public final static int S_SYMBOL_STUBS                          = 0x8;
	/** Type: section with only function pointers for initialization*/
	public final static int S_MOD_INIT_FUNC_POINTERS                = 0x9;
	/** Type: section with only function pointers for termination */
	public final static int S_MOD_TERM_FUNC_POINTERS                = 0xa;
	/** Type: section contains symbols that are to be coalesced */
	public final static int S_COALESCED                             = 0xb;
	/** Type: zero fill on demand section (that can be larger than 4 gigabytes) */
	public final static int S_GB_ZEROFILL                           = 0xc;
	/** Type: section with only pairs of function pointers for interposing */
	public final static int S_INTERPOSING                           = 0xd;
	/** section with only 16 byte literals */
	public final static int S_16BYTE_LITERALS                       = 0xe;
	/** section contains DTrace Object Format */
	public final static int S_DTRACE_DOF                            = 0xf;
	/** section with only lazy symbol pointers to lazy loaded dylibs */
	public final static int S_LAZY_DYLIB_SYMBOL_POINTERS            = 0x10;

	/**
	 * Section types to support thread local variables.
	 * Template of initial values to TLVs.
	 */
	public final static int S_THREAD_LOCAL_REGULAR                  = 0x11;
	/**
	 * Section types to support thread local variables.
	 * Template of initial values to TLVs.
	 */
	public final static int S_THREAD_LOCAL_ZEROFILL                 = 0x12;
	/**
	 * Section types to support thread local variables.
	 * TLV descriptors.
	 */
	public final static int S_THREAD_LOCAL_VARIABLES                = 0x13;
	/**
	 * Section types to support thread local variables.
	 * Pointers to TLV descriptors.
	 */
	public final static int S_THREAD_LOCAL_VARIABLE_POINTERS        = 0x14;
	/**
	 * Section types to support thread local variables.
	 * Functions to call to initialize TLV values.
	 */
	public final static int S_THREAD_LOCAL_INIT_FUNCTION_POINTERS   = 0x15;

	/**
	 * Returns the string name for the constant define of the section type.
	 * @param type the section type
	 * @return string name for the constant define of the section type
	 */
	public final static String getTypeName( int type ) {
		Field [] fields = SectionTypes.class.getDeclaredFields();
		for (Field field : fields) {
			if (field.getName().startsWith("S_")) {
				try {
					Integer value = (Integer)field.get(null);
					if (value == type) {
						return field.getName().substring("S_".length());
					}
				}
				catch (Exception e) {
				}
			}
		}
		return "Unrecognized_Section_Type_0x"+Integer.toHexString(type);
	}
}
