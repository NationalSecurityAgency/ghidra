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

/**
 * class for elf_msp430x_reloc_type (from binutils source)
 */
public class MSP430X_ElfRelocationConstants {
	// Note: some of the msp430x relocation types have "msp430" (without the x) 
	// in their names
	public static final int R_MSP430_NONE = 0; // No calculation
	public static final int R_MSP430_ABS32 = 1;// S + A
	public static final int R_MSP430_ABS16 = 2; // S + A
	public static final int R_MSP430_ABS8 = 3; // S + A
	public static final int R_MSP430_PCR16 = 4; // S + A - PC
	public static final int R_MSP430X_PCR20_EXT_SRC = 5; // S + A - PC
	public static final int R_MSP430X_PCR20_EXT_DST = 6; // S + A - PC
	public static final int R_MSP430X_PCR20_EXT_ODST = 7; // S + A - PC
	public static final int R_MSP430X_ABS20_EXT_SRC = 8; // S + A
	public static final int R_MSP430X_ABS20_EXT_DST = 9; // S + A
	public static final int R_MSP430X_ABS20_EXT_ODST = 10; // S + A
	public static final int R_MSP430X_ABS20_ADR_SRC = 11; // S + A
	public static final int R_MSP430X_ABS20_ADR_DST = 12; // S + A
	public static final int R_MSP430X_PCR16 = 13; // S + A - PC
	public static final int R_MSP430X_PCR20_CALL = 14; // S + A - PC
	public static final int R_MSP430X_ABS16 = 15; // S + A
	public static final int R_MSP430_ABS_HI16 = 16; // S + A (Rela only)
	public static final int R_MSP430_PREL31 = 17; // S + A - PC
	public static final int R_MSP430_EHTYPE = 18; // encodes typeinfo addresses in exception tables
	public static final int R_MSP430X_10_PCREL = 19; // Red Hat invention.
	public static final int R_MSP430X_2X_PCREL = 20; // Red Hat invention
	public static final int R_MSP430X_SYM_DIFF = 21; // Red Hat invention*/
	public static final int R_MSP430X_SET_ULEB128 = 22; // GNU only
	public static final int R_MSP430X_SUB_ULEB128 = 23; // GNU only

	private MSP430X_ElfRelocationConstants() {
		//class not for instantiation
	}

}
