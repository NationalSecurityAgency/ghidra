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
package ghidra.app.util.bin.format.dwarf;

public class DWARFLocationListEntry {

	public static final int DW_LLE_end_of_list = 0x00;
	public static final int DW_LLE_base_addressx = 0x01;
	public static final int DW_LLE_startx_endx = 0x02;
	public static final int DW_LLE_startx_length = 0x03;
	public static final int DW_LLE_offset_pair = 0x04;
	public static final int DW_LLE_default_location = 0x05;
	public static final int DW_LLE_base_address = 0x06;
	public static final int DW_LLE_start_end = 0x07;
	public static final int DW_LLE_start_length = 0x08;

	public static String toString(long value) {
		return DWARFUtil.toString(DWARFLocationListEntry.class, value);
	}

}
