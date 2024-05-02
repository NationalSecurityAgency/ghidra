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

public class DWARFUnitType {
	public static final int DW_UT_compile = 0x01;
	public static final int DW_UT_type = 0x02;
	public static final int DW_UT_partial = 0x03;
	public static final int DW_UT_skeleton = 0x04;
	public static final int DW_UT_split_compile = 0x05;
	public static final int DW_UT_split_type = 0x06;

	public static final int DW_UT_lo_user = 0x80;
	public static final int DW_UT_hi_user = 0xff;

}
