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

public class PowerPC_ElfRelocationConstants {

	public static final int R_PPC_NONE = 0;
	public static final int R_PPC_ADDR32 = 1; // word32 S + A
	public static final int R_PPC_ADDR24 = 2; // low24 (S + A) >> 2
	public static final int R_PPC_ADDR16 = 3; // half16 S + A
	public static final int R_PPC_ADDR16_LO = 4; // half16 #lo(S + A)
	public static final int R_PPC_ADDR16_HI = 5; // half16 #hi(S + A)
	public static final int R_PPC_ADDR16_HA = 6; // half16 #ha(S + A)
	public static final int R_PPC_ADDR14 = 7; // low14 (S + A) >> 2
	public static final int R_PPC_ADDR14_BRTAKEN = 8; // low14 (S + A) >> 2
	public static final int R_PPC_ADDR14_BRNTAKEN = 9; // low14 (S + A) >> 2
	public static final int R_PPC_REL24 = 10; // low24 (S + A - P) >> 2
	public static final int R_PPC_REL14 = 11; // low14 (S + A - P) >> 2
	public static final int R_PPC_REL14_BRTAKEN = 12; // low14 (S + A - P) >>
														// 2
	public static final int R_PPC_REL14_BRNTAKEN = 13; // low14 (S + A - P) >>
														// 2
	public static final int R_PPC_GOT16 = 14; // half16 G + A
	public static final int R_PPC_GOT16_LO = 15; // half16 #lo(G + A)
	public static final int R_PPC_GOT16_HI = 16; // half16 #hi(G + A)
	public static final int R_PPC_GOT16_HA = 17; // half16 #ha(G + A)
	public static final int R_PPC_PLTREL24 = 18; // low24 (L + A + P) >> 2
	public static final int R_PPC_COPY = 19; // none none
	public static final int R_PPC_GLOB_DAT = 20; // word32 S + A
	public static final int R_PPC_JMP_SLOT = 21; // Old ABI: word32 S + A, New ABI: generate branch instruction
	public static final int R_PPC_RELATIVE = 22; // word32 S + A
	public static final int R_PPC_LOCAL24PC = 23; // none
	public static final int R_PPC_UADDR32 = 24; // low24
	public static final int R_PPC_UADDR16 = 25; // half16 S + A
	public static final int R_PPC_REL32 = 26; // word32 S + A - P
	public static final int R_PPC_PLT32 = 27; // word32 L + A
	public static final int R_PPC_PLTREL32 = 28; // word32 L + A - P
	public static final int R_PPC_PLT16_LO = 29; // half16 #lo(L + A)
	public static final int R_PPC_PLT16_HI = 30; // half16 #hi(L + A)
	public static final int R_PPC_PLT16_HA = 31; // half16 #ha(L + A)
	public static final int R_PPC_SDAREL16 = 32; // half16 S + A - _SDA_BASE_
	public static final int R_PPC_SECTOFF = 33; // half16 R + A
	public static final int R_PPC_SECTOFF_LO = 34; // half16 #lo(R + A)
	public static final int R_PPC_SECTOFF_HI = 35; // half16 #hi(R + A)
	public static final int R_PPC_SECTOFF_HA = 36; // half16 #ha(R + A)
	public static final int R_PPC_ADDR30 = 37; // word30 (S + A - P) >> 2

	// Masks for manipulating Power PC relocation targets
	public static final int PPC_WORD32 = 0xFFFFFFFF;
	public static final int PPC_WORD30 = 0xFFFFFFFC;
	public static final int PPC_LOW24 = 0x03FFFFFC;
	public static final int PPC_LOW14 = 0x0020FFFC;
	public static final int PPC_HALF16 = 0xFFFF;

	private PowerPC_ElfRelocationConstants() {
		// no construct
	}
}
