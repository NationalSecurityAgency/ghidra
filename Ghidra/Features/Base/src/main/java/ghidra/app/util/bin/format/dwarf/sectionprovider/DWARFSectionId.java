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
package ghidra.app.util.bin.format.dwarf.sectionprovider;

/**
 * Enum specifying common DWARF sections
 */
public enum DWARFSectionId {
	DEBUG_INFO("debug_info"),
	DEBUG_TYPES("debug_types"),
	DEBUG_ABBREV("debug_abbrev"),
	DEBUG_ARRANGES("debug_arranges"),
	DEBUG_LINE("debug_line"),
	DEBUG_LINE_STR("debug_line_str"), // v5+
	DEBUG_FRAME("debug_frame"),
	DEBUG_LOC("debug_loc"),
	DEBUG_LOCLISTS("debug_loclists"), // v5+
	DEBUG_STR("debug_str"),
	DEBUG_STROFFSETS("debug_str_offsets"), // v5+
	DEBUG_RANGES("debug_ranges"),
	DEBUG_RNGLISTS("debug_rnglists"), // v5+
	DEBUG_PUBNAMES("debug_pubnames"),
	DEBUG_PUBTYPES("debug_pubtypes"),
	DEBUG_MACINFO("debug_macinfo"),
	DEBUG_MACRO("debug_macro"), // v5+
	DEBUG_ADDR("debug_addr");

	public static final String[] MINIMAL_DWARF_SECTIONS =
		new String[] { DEBUG_INFO.getSectionName(), DEBUG_ABBREV.getSectionName() };

	private final String name;

	private DWARFSectionId(String name) {
		this.name = name;
	}

	public String getSectionName() {
		return name;
	}
}
