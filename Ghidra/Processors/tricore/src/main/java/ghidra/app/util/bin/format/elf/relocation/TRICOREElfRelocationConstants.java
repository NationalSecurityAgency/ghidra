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
package ghidra.app.util.bin.format.elf.relocation;

public class TRICOREElfRelocationConstants {

	// e_flags Identifying TriCore/PCP Derivatives
	public static final int EF_TRICORE_V1_1 = 0x80000000;
	public static final int EF_TRICORE_V1_2 = 0x40000000;
	public static final int EF_TRICORE_V1_3 = 0x20000000;
	public static final int EF_TRICORE_PCP2 = 0x02000000;

	// TriCore Section Attribute Flags
	public static final int SHF_TRICORE_ABS = 0x400;
	public static final int SHF_TRICORE_NOREAD = 0x800;

	public static final int R_TRICORE_NONE = 0; //none none
	public static final int R_TRICORE_32REL = 1; //word32 S + A - P
	public static final int R_TRICORE_32ABS = 2; //word32 S + A
	public static final int R_TRICORE_24REL = 3; //relB S + A - P
	public static final int R_TRICORE_24ABS = 4; //absB S + A
	public static final int R_TRICORE_16SM = 5; //BOL S + A - A[0]
	public static final int R_TRICORE_HI = 6; //RLC S + A + 8000H >> 16
	public static final int R_TRICORE_LO = 7; //RLC S + A & FFFFH
	public static final int R_TRICORE_LO2 = 8; //BOL S + A & FFFFH
	public static final int R_TRICORE_18ABS = 9; //ABS S + A
	public static final int R_TRICORE_10SM = 10; //BO S + A - A[0]
	public static final int R_TRICORE_15REL = 11; //BR S + A - P
	public static final int R_TRICORE_10LI = 12; //BO S + A - A[1]
	public static final int R_TRICORE_16LI = 13; //BOL S + A - A[1]
	public static final int R_TRICORE_10A8 = 14; //BO S + A - A[8]
	public static final int R_TRICORE_16A8 = 15; //BOL S + A - A[8]
	public static final int R_TRICORE_10A9 = 16; //BO S + A - A[9]
	public static final int R_TRICORE_16A9 = 17; //BOL S + A - A[9]
	public static final int R_TRICORE_PCPHI = 25; //word16 S + A >> 16
	public static final int R_TRICORE_PCPLO = 26; //word16 S + A & FFFFH
	public static final int R_TRICORE_PCPPAGE = 27; //pcpPage S + A & FF00H
	public static final int R_TRICORE_PCPOFF = 28; //PI (S + A >> 2) & 3FH
	public static final int R_TRICORE_PCPTEXT = 29; //word16 (S + A >> 1) & FFFFH
}
