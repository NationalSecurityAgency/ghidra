/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.macho;

public enum RelocationTypeARM64 {

	/** for pointers */
	ARM64_RELOC_UNSIGNED,

	/** must be followed but an ARM64_RELOC_UNSIGNED */
	ARM64_RELOC_SUBTRACTOR,

	/** b/bl instruction with 26-bit displacement */
	ARM64_RELOC_BRANCH26,

	/** PC-rel distance to page of target */
	ARM64_RELOC_PAGE21,

	/** offset within page, scaled by r_length */
	ARM64_RELOC_PAGEOFF12,

	/** PC-rel distance to page of GOT slot */
	ARM64_RELOC_GOT_LOAD_PAGE21,

	/** offset within page of GOT slot, scaled by r_length */
	ARM64_RELOC_GOT_LOAD_PAGEOFF12,

	/** for pointers to GOT slots*/
	ARM64_RELOC_POINTER_TO_GOT,

	/** PC-rel distance to page of TLVP slot */
	ARM64_RELOC_TLVP_LOAD_PAGE21,

	/** offset within page of TLVP slot, scaled by r_length */
	ARM64_RELOC_TLVP_LOAD_PAGEOFF12,

	/** must be followed by ARM64_RELOC_PAGE21 or ARM64_RELOC_PAGEOFF12 */
	ARM64_RELOC_ADDEND;

}
