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
 * {@link AARCH64_MachoRelocationHandler} constants
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/arm64/reloc.h.auto.html">mach-o/arm64/reloc.h</a> 
 */
public class AARCH64_MachoRelocationConstants {

	/**
	 * For pointers
	 */
	public final static int ARM64_RELOC_UNSIGNED = 0;

	/**
	 * Must be followed by a ARM64_RELOC_UNSIGNED
	 */
	public final static int ARM64_RELOC_SUBTRACTOR = 1;

	/**
	 * A B/BL instruction with 26-bit displacement
	 */
	public final static int ARM64_RELOC_BRANCH26 = 2;

	/**
	 * PC-rel distance to page of target
	 */
	public final static int ARM64_RELOC_PAGE21 = 3;

	/**
	 * Offset within page, scaled by r_length
	 */
	public final static int ARM64_RELOC_PAGEOFF12 = 4;

	/**
	 * PC-rel distance to page of GOT slot
	 */
	public final static int ARM64_RELOC_GOT_LOAD_PAGE21 = 5;

	/**
	 * Offset within page of GOT slot, scaled by r_length
	 */
	public final static int ARM64_RELOC_GOT_LOAD_PAGEOFF12 = 6;

	/**
	 * For pointers to GOT slots
	 */
	public final static int ARM64_RELOC_POINTER_TO_GOT = 7;

	/**
	 * PC-rel distance to page of TLVP slot
	 */
	public final static int ARM64_RELOC_TLVP_LOAD_PAGE21 = 8;

	/**
	 * Offset within page of TLVP slot, scaled by r_length
	 */
	public final static int ARM64_RELOC_TLVP_LOAD_PAGEOFF12 = 9;

	/**
	 * Must be followed by PAGE21 or PAGEOFF12
	 */
	public final static int ARM64_RELOC_ADDEND = 10;
	
	/**
	 * Like ARM64_RELOC_UNSIGNED, but addend in lower 32-bits
	 */
	public final static int ARM64_RELOC_AUTHENTICATED_POINTER = 11;
}
