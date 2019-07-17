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

public class PowerPC64_ElfRelocationConstants {

	public static final int R_PPC64_NONE = 0; 
	public static final int R_PPC64_ADDR32 = 1; 			// word32*       S + A
	public static final int R_PPC64_ADDR24 = 2; 			// low24*        (S + A) >> 2
	public static final int R_PPC64_ADDR16 = 3; 			// half16*       S + A
	public static final int R_PPC64_ADDR16_LO = 4; 		// half16        #lo(S + A)
	public static final int R_PPC64_ADDR16_HI = 5; 		// half16        #hi(S + A)
	public static final int R_PPC64_ADDR16_HA = 6; 		// half16        #ha(S + A)
	public static final int R_PPC64_ADDR14 = 7; 			// low14*        (S + A) >> 2
	public static final int R_PPC64_ADDR14_BRTAKEN = 8; 	// low14*        (S + A) >> 2
	public static final int R_PPC64_ADDR14_BRNTAKEN = 9; // low14*       (S + A) >> 2
	public static final int R_PPC64_REL24 = 10; 			// low24*        (S + A - P) >> 2
	public static final int R_PPC64_REL14 = 11; 			// low14*        (S + A - P) >> 2
	public static final int R_PPC64_REL14_BRTAKEN = 12; 	// low14*        (S + A - P) >> 2
	public static final int R_PPC64_REL14_BRNTAKEN = 13; // low14*       (S + A - P) >> 2
	public static final int R_PPC64_GOT16 = 14; 			// half16*       G
	public static final int R_PPC64_GOT16_LO = 15; 		// half16        #lo(G)
	public static final int R_PPC64_GOT16_HI = 16; 		// half16        #hi(G)
	public static final int R_PPC64_GOT16_HA = 17; 		// half16        #ha(G)
	public static final int R_PPC64_COPY = 19;
	public static final int R_PPC64_GLOB_DAT = 20; 		// doubleword64  S + A
	public static final int R_PPC64_JMP_SLOT = 21; 		// none          see below
	public static final int R_PPC64_RELATIVE = 22; 		// doubleword64  B + A
	public static final int R_PPC64_UADDR32 = 24; 		// word32*       S + A
	public static final int R_PPC64_UADDR16 = 25; 		// half16*       S + A
	public static final int R_PPC64_REL32 = 26; 			// word32*       S + A - P
	public static final int R_PPC64_PLT32 = 27; 			// word32*       L
	public static final int R_PPC64_PLTREL32 = 28; 		// word32*       L - P
	public static final int R_PPC64_PLT16_LO = 29; 		// half16        #lo(L)
	public static final int R_PPC64_PLT16_HI = 30; 		// half16        #hi(L)
	public static final int R_PPC64_PLT16_HA = 31; 		// half16        #ha(L)
	public static final int R_PPC64_SECTOFF = 33; 		// half16*       R + A
	public static final int R_PPC64_SECTOFF_LO = 34; 	// half16        #lo(R + A)
	public static final int R_PPC64_SECTOFF_HI = 35; 	// half16        #hi(R + A)
	public static final int R_PPC64_SECTOFF_HA = 36; 	// half16        #ha(R + A)
	public static final int R_PPC64_ADDR30 = 37; 		// word30        (S + A - P) >> 2
	public static final int R_PPC64_ADDR64 = 38; 		// doubleword64  S + A
	public static final int R_PPC64_ADDR16_HIGHER = 39; 	// half16        #higher(S + A)
	public static final int R_PPC64_ADDR16_HIGHERA = 40; // half16       #highera(S + A)
	public static final int R_PPC64_ADDR16_HIGHEST = 41; // half16       #highest(S + A)
	public static final int R_PPC64_ADDR16_HIGHESTA = 42; // half16      #highesta(S + A)
	public static final int R_PPC64_UADDR64 = 43; 		// doubleword64  S + A
	public static final int R_PPC64_REL64 = 44; 			// doubleword64  S + A - P
	public static final int R_PPC64_PLT64 = 45; 			// doubleword64  L
	public static final int R_PPC64_PLTREL64 = 46; 		// doubleword64  L - P
	public static final int R_PPC64_TOC16 = 47; 			// half16*       S + A - .TOC.
	public static final int R_PPC64_TOC16_LO = 48; 		// half16        #lo(S + A - .TOC.)
	public static final int R_PPC64_TOC16_HI = 49; 		// half16        #hi(S + A - .TOC.)
	public static final int R_PPC64_TOC16_HA = 50; 		// half16        #ha(S + A - .TOC.)
	public static final int R_PPC64_TOC = 51; 			// doubleword64  .TOC.
	public static final int R_PPC64_PLTGOT16 = 52; 		// half16*       M
	public static final int R_PPC64_PLTGOT16_LO = 53; 	// half16        #lo(M)
	public static final int R_PPC64_PLTGOT16_HI = 54; 	// half16        #hi(M)
	public static final int R_PPC64_PLTGOT16_HA = 55; 	// half16        #ha(M)
	public static final int R_PPC64_ADDR16_DS = 56; 		// half16ds*     (S + A) >> 2
	public static final int R_PPC64_ADDR16_LO_DS = 57; 	// half16ds      #lo(S + A) >> 2
	public static final int R_PPC64_GOT16_DS = 58; 		// half16ds*     G >> 2
	public static final int R_PPC64_GOT16_LO_DS = 59; 	// half16ds      #lo(G) >> 2
	public static final int R_PPC64_PLT16_LO_DS = 60; 	// half16ds      #lo(L) >> 2
	public static final int R_PPC64_SECTOFF_DS = 61; 	// half16ds*     (R + A) >> 2
	public static final int R_PPC64_SECTOFF_LO_DS = 62; 	// half16ds      #lo(R + A) >> 2
	public static final int R_PPC64_TOC16_DS = 63; 		// half16ds*     (S + A - .TOC.) >> 2
	public static final int R_PPC64_TOC16_LO_DS = 64; 	// half16ds      #lo(S + A - .TOC.) >> 2
	public static final int R_PPC64_PLTGOT16_DS = 65; 	// half16ds*     M >> 2
	public static final int R_PPC64_PLTGOT16_LO_DS = 66; // half16ds     #lo(M) >> 2
	public static final int R_PPC64_TLS = 67; 
	public static final int R_PPC64_DTPMOD64 = 68; 		// doubleword64  @dtpmod
	public static final int R_PPC64_TPREL16 = 69; 		// half16*       @tprel
	public static final int R_PPC64_TPREL16_LO = 60; 	// half16        #lo(@tprel)
	public static final int R_PPC64_TPREL16_HI = 71; 	// half16        #hi(@tprel)
	public static final int R_PPC64_TPREL16_HA = 72; 	// half16        #ha(@tprel)
	public static final int R_PPC64_TPREL64 = 73; 		// doubleword64  @tprel
	public static final int R_PPC64_DTPREL16 = 74; 		// half16*       @dtprel
	public static final int R_PPC64_DTPREL16_LO = 75; 	// half16        #lo(@dtprel)
	public static final int R_PPC64_DTPREL16_HI = 76; 	// half16        #hi(@dtprel)
	public static final int R_PPC64_DTPREL16_HA = 77; 	// half16        #ha(@dtprel)
	public static final int R_PPC64_DTPREL64 = 78; 		// doubleword64  @dtprel
	public static final int R_PPC64_GOT_TLSGD16 = 79; 	// half16*       @got@tlsgd
	public static final int R_PPC64_GOT_TLSGD16_LO = 80; // half16       #lo(@got@tlsgd)
	public static final int R_PPC64_GOT_TLSGD16_HI = 81; // half16       #hi(@got@tlsgd)
	public static final int R_PPC64_GOT_TLSGD16_HA = 82; // half16       #ha(@got@tlsgd)
	public static final int R_PPC64_GOT_TLSLD16 = 83; 	// half16*       @got@tlsld
	public static final int R_PPC64_GOT_TLSLD16_LO = 84; // half16       #lo(@got@tlsld)
	public static final int R_PPC64_GOT_TLSLD16_HI = 85; // half16       #hi(@got@tlsld)
	public static final int R_PPC64_GOT_TLSLD16_HA = 86; // half16       #ha(@got@tlsld)
	public static final int R_PPC64_GOT_TPREL16_DS = 87; // half16ds*    @got@tprel
	public static final int R_PPC64_GOT_TPREL16_LO_DS = 88; // half16ds  #lo(@got@tprel)
	public static final int R_PPC64_GOT_TPREL16_HI = 89; // half16       #hi(@got@tprel)
	public static final int R_PPC64_GOT_TPREL16_HA = 90; // half16       #ha(@got@tprel)
	public static final int R_PPC64_GOT_DTPREL16_DS = 91; // half16ds*   @got@dtprel
	public static final int R_PPC64_GOT_DTPREL16_LO_DS = 92;// half16ds  #lo(@got@dtprel)
	public static final int R_PPC64_GOT_DTPREL16_HI = 93; // half16      #hi(@got@dtprel)
	public static final int R_PPC64_GOT_DTPREL16_HA = 94; // half16      #ha(@got@dtprel)
	public static final int R_PPC64_TPREL16_DS = 95; 	// half16ds*     @tprel
	public static final int R_PPC64_TPREL16_LO_DS = 96; 	// half16ds      #lo(@tprel)
	public static final int R_PPC64_TPREL16_HIGHER = 97; // half16       #higher(@tprel)
	public static final int R_PPC64_TPREL16_HIGHERA = 98; // half16      #highera(@tprel)
	public static final int R_PPC64_TPREL16_HIGHEST = 99; // half16      #highest(@tprel)
	public static final int R_PPC64_TPREL16_HIGHESTA = 100; // half16    #highesta(@tprel)
	public static final int R_PPC64_DTPREL16_DS = 101; 	// half16ds*     @dtprel
	public static final int R_PPC64_DTPREL16_LO_DS = 102; // half16ds    #lo(@dtprel)
	public static final int R_PPC64_DTPREL16_HIGHER = 103; // half16     #higher(@dtprel)
	public static final int R_PPC64_DTPREL16_HIGHERA = 104; // half16    #highera(@dtprel)
	public static final int R_PPC64_DTPREL16_HIGHEST = 105; // half16    #highest(@dtprel)
	public static final int R_PPC64_DTPREL16_HIGHESTA = 106; // half16   #highesta(@dtprel)

	// Masks for manipulating Power PC relocation targets
	public static final int PPC64_WORD32 = 0xFFFFFFFF;
	public static final int PPC64_WORD30 = 0xFFFFFFFC;
	public static final int PPC64_LOW24 = 0x03FFFFFC;
	public static final int PPC64_LOW14 = 0x0020FFFC;
	public static final int PPC64_HALF16 = 0xFFFF;
		
	private PowerPC64_ElfRelocationConstants() {
		// no construct
	}
}
