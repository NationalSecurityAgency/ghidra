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

public class X86_32_ElfRelocationConstants {

	public static final int R_386_NONE = 0; // No calculation
	public static final int R_386_32 = 1; // S + A
	public static final int R_386_PC32 = 2; // S + A - P
	public static final int R_386_GOT32 = 3; // G + A - P
	public static final int R_386_PLT32 = 4; // L + A - P
	public static final int R_386_COPY = 5; // No calculation
	public static final int R_386_GLOB_DAT = 6; // S
	public static final int R_386_JMP_SLOT = 7; // S
	public static final int R_386_RELATIVE = 8; // B + A
	public static final int R_386_GOTOFF = 9; // S + A - GOT
	public static final int R_386_GOTPC = 10; // GOT + A - P
	public static final int R_386_32PLT = 11;

	public static final int R_386_TLS_TPOFF = 14; // negative offset in static TLS block
	public static final int R_386_TLS_IE = 15; // absolute address of GOT entry for negative static TLS block offset
	public static final int R_386_TLS_GOTIE = 16; // GOT entry for negative static TLS block offset
	public static final int R_386_TLS_LE = 17; // negative offset relative to static TLS
	public static final int R_386_TLS_GD = 18; // direct 32 bit for GNU version of GD TLS
	public static final int R_386_TLS_LDM = 19; // direct 32 bit for GNU version of LD TLS in LE code
	public static final int R_386_TLS_GD_32 = 24; // direct 32 bit for GD TLS
	public static final int R_386_TLS_GD_PUSH = 25; // tag for pushl in GD TLS code
	public static final int R_386_TLS_GD_CALL = 26; // relocation for call 
	public static final int R_386_TLS_GD_POP = 27; // tag for popl in GD TLS code
	public static final int R_386_TLS_LDM_32 = 28; // direct 32 bit for local dynamic code
	public static final int R_386_TLS_LDM_PUSH = 29; // tag for pushl in LDM TLS code
	public static final int R_386_TLS_LDM_CALL = 30; // relocation for call 
	public static final int R_386_TLS_LDM_POP = 31; // tag for popl in LDM TLS code
	public static final int R_386_TLS_LDO_32 = 32; // offset relative to TLS block
	public static final int R_386_TLS_IE_32 = 33; // got entry for static TLS block
	public static final int R_386_TLS_LE_32 = 34; // offset relative to static TLS block
	public static final int R_386_TLS_DTPMOD32 = 35; // ID of module containing symbol
	public static final int R_386_TLS_DTPOFF32 = 36; // offset in TLS block
	public static final int R_386_TLS_TPOFF32 = 37; // offset in static TLS block
	public static final int R_386_TLS_GOTDESC = 39; // GOT offset for TLS descriptor.  */
	public static final int R_386_TLS_DESC_CALL = 40; // Marker of call through TLS descriptor for relaxation.  */
	public static final int R_386_TLS_DESC = 41; // TLS descriptor containing pointer to code and to argument, returning the TLS offset for the symbol.  */
	public static final int R_386_IRELATIVE = 42; // Adjust indirectly by program base */

	private X86_32_ElfRelocationConstants() {
		// no construct
	}
}
