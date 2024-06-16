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
package ghidra.app.util.bin.format.macho.relocation;

/** 
 * {@link PowerPC_MachoRelocationHandler} constants
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-1504.9.37/EXTERNAL_HEADERS/mach-o/ppc/reloc.h.auto.html">mach-o/ppc/reloc.h</a> 
 */
public class PowerPC_MachoRelocationConstants {

	/**
	 * Generic relocation as described above
	 */
	public final static int PPC_RELOC_VANILLA = 0;

	/**
	 * The second relocation entry of a pair
	 */
	public final static int PPC_RELOC_PAIR = 1;

	/**
	 * 14 bit branch displacement (to a word address)
	 */
	public final static int PPC_RELOC_BR14 = 2;

	/**
	 * 24 bit branch displacement (to a word address)
	 */
	public final static int PPC_RELOC_BR24 = 3;

	/**
	 * A {@link #PPC_RELOC_PAIR} follows with the low half
	 */
	public final static int PPC_RELOC_HI16 = 4;

	/**
	 * A {@link #PPC_RELOC_PAIR} follows with the high half
	 */
	public final static int PPC_RELOC_LO16 = 5;

	/**
	 * Same as the {@link #PPC_RELOC_HI16} except the low 16 bits and the high 16 bits are added 
	 * together with the low 16 bits sign-extended first.  This means if bit 15 of the low 16 bits
	 * is set the high 16 bits stored in the instruction will be adjusted.
	 */
	public final static int PPC_RELOC_HA16 = 6;

	/**
	 * Same as the {@link #PPC_RELOC_LO16} except that the low 2 bits are not stored in the 
	 * instruction and are always zero.  This is used in double word load/store instructions.
	 */
	public final static int PPC_RELOC_LO14 = 7;

	/**
	 * A {@link #PPC_RELOC_PAIR} follows with subtract symbol value
	 */
	public final static int PPC_RELOC_SECTDIFF = 8;

	/**
	 * Pre-bound lazy pointer
	 */
	public final static int PPC_RELOC_PB_LA_PTR = 9;

	/**
	 * A section difference forms of above. 
	 * A {@link #PPC_RELOC_PAIR} Follows these with subtract symbol value.
	 */
	public final static int PPC_RELOC_HI16_SECTDIFF = 10;
	public final static int PPC_RELOC_LO16_SECTDIFF = 11;
	public final static int PPC_RELOC_HA16_SECTDIFF = 12;
	public final static int PPC_RELOC_JBSR = 13;
	public final static int PPC_RELOC_LO14_SECTDIFF = 14;

	/**
	 * Like {@link #PPC_RELOC_SECTDIFF}, but the symbol referenced was local.
	 */
	public final static int PPC_RELOC_LOCAL_SECTDIFF = 15;
}

