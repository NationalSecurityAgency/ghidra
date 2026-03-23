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

public class Hexagon_ElfConstants {

	// Hexagon-specific e_flags

	// Object processor version flags, bits[11:0]
	public static final int EF_HEXAGON_MACH_V2 = 0x00000001;   // Hexagon V2
	public static final int EF_HEXAGON_MACH_V3 = 0x00000002;   // Hexagon V3
	public static final int EF_HEXAGON_MACH_V4 = 0x00000003;   // Hexagon V4
	public static final int EF_HEXAGON_MACH_V5 = 0x00000004;   // Hexagon V5
	public static final int EF_HEXAGON_MACH_V55 = 0x00000005;  // Hexagon V55
	public static final int EF_HEXAGON_MACH_V60 = 0x00000060;  // Hexagon V60
	public static final int EF_HEXAGON_MACH_V62 = 0x00000062;  // Hexagon V62
	public static final int EF_HEXAGON_MACH_V65 = 0x00000065;  // Hexagon V65
	public static final int EF_HEXAGON_MACH_V66 = 0x00000066;  // Hexagon V66
	public static final int EF_HEXAGON_MACH_V67 = 0x00000067;  // Hexagon V67
	public static final int EF_HEXAGON_MACH_V67T = 0x00008067; // Hexagon V67T
	public static final int EF_HEXAGON_MACH_V68 = 0x00000068;  // Hexagon V68
	public static final int EF_HEXAGON_MACH_V69 = 0x00000069;  // Hexagon V69
	public static final int EF_HEXAGON_MACH_V71 = 0x00000071;  // Hexagon V71
	public static final int EF_HEXAGON_MACH_V71T = 0x00008071; // Hexagon V71T
	public static final int EF_HEXAGON_MACH_V73 = 0x00000073;  // Hexagon V73
	public static final int EF_HEXAGON_MACH = 0x000003ff;      // Hexagon V..

	// Highest ISA version flags
	public static final int EF_HEXAGON_ISA_MACH = 0x00000000; // Same as specified in bits[11:0] of e_flags
	public static final int EF_HEXAGON_ISA_V2 = 0x00000010;   // Hexagon V2 ISA
	public static final int EF_HEXAGON_ISA_V3 = 0x00000020;   // Hexagon V3 ISA
	public static final int EF_HEXAGON_ISA_V4 = 0x00000030;   // Hexagon V4 ISA
	public static final int EF_HEXAGON_ISA_V5 = 0x00000040;   // Hexagon V5 ISA
	public static final int EF_HEXAGON_ISA_V55 = 0x00000050;  // Hexagon V55 ISA
	public static final int EF_HEXAGON_ISA_V60 = 0x00000060;  // Hexagon V60 ISA
	public static final int EF_HEXAGON_ISA_V62 = 0x00000062;  // Hexagon V62 ISA
	public static final int EF_HEXAGON_ISA_V65 = 0x00000065;  // Hexagon V65 ISA
	public static final int EF_HEXAGON_ISA_V66 = 0x00000066;  // Hexagon V66 ISA
	public static final int EF_HEXAGON_ISA_V67 = 0x00000067;  // Hexagon V67 ISA
	public static final int EF_HEXAGON_ISA_V68 = 0x00000068;  // Hexagon V68 ISA
	public static final int EF_HEXAGON_ISA_V69 = 0x00000069;  // Hexagon V69 ISA
	public static final int EF_HEXAGON_ISA_V71 = 0x00000071;  // Hexagon V71 ISA
	public static final int EF_HEXAGON_ISA_V73 = 0x00000073;  // Hexagon V73 ISA
	public static final int EF_HEXAGON_ISA_V75 = 0x00000075;  // Hexagon V75 ISA
	public static final int EF_HEXAGON_ISA = 0x000003ff;     // Hexagon V.. ISA

	// Hexagon-specific section indexes for common small data
	public static final int SHN_HEXAGON_SCOMMON = 0xff00;   // Other access sizes
	public static final int SHN_HEXAGON_SCOMMON_1 = 0xff01; // Byte-sized access
	public static final int SHN_HEXAGON_SCOMMON_2 = 0xff02; // Half-word-sized access
	public static final int SHN_HEXAGON_SCOMMON_4 = 0xff03; // Word-sized access
	public static final int SHN_HEXAGON_SCOMMON_8 = 0xff04;  // Double-word-size access

	private Hexagon_ElfConstants() {
		// no construct
	}

}
