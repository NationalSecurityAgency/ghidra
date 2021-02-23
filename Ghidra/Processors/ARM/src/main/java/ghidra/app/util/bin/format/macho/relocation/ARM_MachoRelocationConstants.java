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
 * {@link ARM_MachoRelocationHandler} constants
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/arm/reloc.h.auto.html">mach-o/arm/reloc.h</a> 
 */
public class ARM_MachoRelocationConstants {
	
	/**
	 * Generic relocation as described above
	 */
	public final static int ARM_RELOC_VANILLA = 0;

	/**
	 * The second relocation entry of a pair
	 */
	public final static int ARM_RELOC_PAIR = 1;

	/**
	 * A PAIR follows with subtract symbol value
	 */
	public final static int ARM_RELOC_SECTDIFF = 2;

	/**
	 * Like ARM_RELOC_SECTDIFF, but the symbol referenced was local
	 */
	public final static int ARM_RELOC_LOCAL_SECTDIFF = 3;

	/**
	 * Pre-bound lazy pointer
	 */
	public final static int ARM_RELOC_PB_LA_PTR = 4;

	/**
	 * 24 bit branch displacement (to a word address)
	 */
	public final static int ARM_RELOC_BR24 = 5;

	/**
	 * 22 bit branch displacement (to a half-word address)
	 */
	public final static int ARM_THUMB_RELOC_BR22 = 6;

	/**
	 * Obsolete - a thumb 32-bit branch instruction possibly needing page-spanning branch workaround
	 */
	public final static int ARM_THUMB_32BIT_BRANCH = 7;

	/**
	 * For these two r_type relocations they always have a pair following them and the r_length bits
	 * are used differently.  The encoding of the r_length is as follows:
	 * 
	 * low bit of r_length:
	 *    0 - :lower16: for movw instructions
	 *    1 - :upper16: for movt instructions
	 *    
	 * high bit of r_length:
	 *    0 - arm instructions
	 *    1 - thumb instructions
	 *       
	 * The other half of the relocated expression is in the following pair relocation entry in the 
	 * low 16 bits of r_address field.
	 */
	public final static int ARM_RELOC_HALF = 8;
	public final static int ARM_RELOC_HALF_SECTDIFF = 9;
}
