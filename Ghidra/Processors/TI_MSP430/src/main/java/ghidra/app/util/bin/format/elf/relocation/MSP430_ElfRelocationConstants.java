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
 * class for elf_msp430_reloc_type (from binutils source)
 */
public class MSP430_ElfRelocationConstants {
	public static final int R_MSP430_NONE = 0;
	public static final int R_MSP430_32 = 1;
	public static final int R_MSP430_10_PCREL = 2;
	public static final int R_MSP430_16 = 3;
	public static final int R_MSP430_16_PCREL = 4;
	public static final int R_MSP430_16_BYTE = 5;
	public static final int R_MSP430_16_PCREL_BYTE = 6;
	public static final int R_MSP430_2X_PCREL = 7;
	public static final int R_MSP430_RL_PCREL = 8;
	public static final int R_MSP430_8 = 9;
	public static final int R_MSP430_SYM_DIFF = 10;
	public static final int R_MSP430_SET_ULEB128 = 11; // GNU only.  
	public static final int R_MSP430_SUB_ULEB128 = 12; // GNU only 
}
