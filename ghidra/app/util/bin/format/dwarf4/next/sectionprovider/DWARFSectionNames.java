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
package ghidra.app.util.bin.format.dwarf4.next.sectionprovider;

public final class DWARFSectionNames {
	public static final String DEBUG_INFO = "debug_info";
	public static final String DEBUG_TYPES = "debug_types";
	public static final String DEBUG_ABBREV = "debug_abbrev";
	public static final String DEBUG_ARRANGES = "debug_arranges";
	public static final String DEBUG_LINE = "debug_line";
	public static final String DEBUG_FRAME = "debug_frame";
	public static final String DEBUG_LOC = "debug_loc";
	public static final String DEBUG_STR = "debug_str";
	public static final String DEBUG_RANGES = "debug_ranges";
	public static final String DEBUG_PUBNAMES = "debug_pubnames";
	public static final String DEBUG_PUBTYPES = "debug_pubtypes";
	public static final String DEBUG_MACINFO = "debug_macinfo";
	
	public static final String[] MINIMAL_DWARF_SECTIONS = { DEBUG_INFO, DEBUG_ABBREV };

}
