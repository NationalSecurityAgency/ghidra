/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.dwarf;

import ghidra.app.util.opinion.*;
import ghidra.program.model.listing.Program;

public final class DwarfSectionNames {
	private final static String MACHO_PREFIX = "__";
	private final static String   ELF_PREFIX = ".";

	private String prefix = "";

	/**
	 * Creates a new Dwarf Section Names for the specific program.
	 * @param program the program containing dwarf debug information.
	 * @throws IllegalArgumentException if the program's format is not handled.
	 */
	public DwarfSectionNames(Program program) {
		if (MachoLoader.MACH_O_NAME.equals(program.getExecutableFormat())) {
			prefix = MACHO_PREFIX;
		}
		else if (ElfLoader.ELF_NAME.equals(program.getExecutableFormat())) {
			prefix = ELF_PREFIX;
		}
		else {
			throw new IllegalArgumentException("Unrecognized program format: "+program.getExecutableFormat());
		}
	}

	/**
	 * Holds tag, attribute names, and attribute forms encodings
	 */
	public String SECTION_NAME_ABBREV() { return prefix+"debug_abbrev"; }
	/**
	 * A mapping between memory address and compilation
	 */
	public String SECTION_NAME_ARANGES() { return prefix+"debug_aranges"; }
	/**
	 * Holds information about call frame activations
	 */
	public String SECTION_NAME_FRAME() { return prefix+"debug_frame"; }
	/**
	 * Debugging information entries for DWARF v2
	 */
	public String SECTION_NAME_INFO() { return prefix+"debug_info"; }
	/**
	 * Line Number Program
	 */
	public String SECTION_NAME_LINE() { return prefix+"debug_line"; }
	/**
	 * Location lists are used in place of location expressions whenever the object whose location is
	 * being described can change location during its lifetime. Location lists are contained in a separate
	 * object file section called .debug_loc. A location list is indicated by a location attribute
	 * whose value is represented as a constant offset from the beginning of the .debug_loc section
	 * to the first byte of the list for the object in question.
	 */
	public String SECTION_NAME_LOC() { return prefix+"debug_loc"; }
	/**
	 * A lookup table for global objects and functions
	 */
	public String SECTION_NAME_MACINFO() { return prefix+"debug_macinfo"; }
	/**
	 * A lookup table for global objects and functions
	 */
	public String SECTION_NAME_PUBNAMES() { return prefix+"debug_pubnames"; }
	/**
	 * A lookup table for global types
	 */
	public String SECTION_NAME_PUBTYPES() { return prefix+"debug_pubtypes"; }
	/**
	 * Address ranges referenced by DIEs
	 */
	public String SECTION_NAME_RANGES() { return prefix+"debug_ranges"; }
	/**
	 * String table used by .debug_info
	 */
	public String SECTION_NAME_STR() { return prefix+"debug_str"; }
}
