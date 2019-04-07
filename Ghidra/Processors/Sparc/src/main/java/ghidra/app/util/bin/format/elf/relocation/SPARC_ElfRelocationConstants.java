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

public class SPARC_ElfRelocationConstants {

	public static final int R_SPARC_NONE = 0; // No calculation
	public static final int R_SPARC_5 = 44; // S + A
	public static final int R_SPARC_6 = 45; // S + A
	public static final int R_SPARC_7 = 43; // S + A
	public static final int R_SPARC_8 = 1; // S + A
	public static final int R_SPARC_10 = 30; // S + A
	public static final int R_SPARC_11 = 31; // S + A
	public static final int R_SPARC_13 = 11; // S + A
	public static final int R_SPARC_16 = 2; // S + A
	public static final int R_SPARC_22 = 10; // S + A
	public static final int R_SPARC_32 = 3; // S + A
	public static final int R_SPARC_LO10 = 12; // (S + A) & 0x3FF
	public static final int R_SPARC_HI22 = 9; // (S + A) >> 10
	public static final int R_SPARC_DISP8 = 4; // S + A - P
	public static final int R_SPARC_DISP16 = 5; // S + A - P
	public static final int R_SPARC_DISP32 = 6; // S + A - P
	public static final int R_SPARC_WDISP16 = 40; // (S + A - P) >> 2
	public static final int R_SPARC_WDISP19 = 41; // (S + A - P) >> 2
	public static final int R_SPARC_WDISP22 = 8; // (S + A - P) >> 2
	public static final int R_SPARC_WDISP30 = 7; // (S + A - P) >> 2
	public static final int R_SPARC_PC10 = 16; // (S + A - P) & 0x3FF
	public static final int R_SPARC_PC22 = 17; // (S + A - P) >> 10
	public static final int R_SPARC_PLT32 = 24; // L + A
	public static final int R_SPARC_PCPLT10 = 29; // (L + A - P) & 0x3FF
	public static final int R_SPARC_PCPLT22 = 28; // (L + A - P) >> 10
	public static final int R_SPARC_PCPLT32 = 27; // L + A - P
	public static final int R_SPARC_GOT10 = 13; // G & 0x3FF
	public static final int R_SPARC_GOT13 = 14; // G
	public static final int R_SPARC_GOT22 = 15; // G >> 10
	public static final int R_SPARC_WPLT30 = 18; // (L + A - P) >> 2
	public static final int R_SPARC_LOPLT10 = 26; // (L + A) & 0x3FF
	public static final int R_SPARC_HIPLT22 = 25; // (L + A) >> 10

	public static final int R_SPARC_JMP_SLOT = 21;
	public static final int R_SPARC_UA32 = 23; // S + A
	public static final int R_SPARC_GLOB_DAT = 20; // S + A
	public static final int R_SPARC_RELATIVE = 22; // B + A
	public static final int R_SPARC_COPY = 19; // No calculation

	private SPARC_ElfRelocationConstants() {
		// no construct
	}
}
