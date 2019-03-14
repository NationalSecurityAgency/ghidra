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

public enum RelocationTypeX86_64 {
	/**
	 * for absolute addresses
	 */
	X86_64_RELOC_UNSIGNED,
	/**
	 * for signed 32-bit displacement
	 */
	X86_64_RELOC_SIGNED,
	/**
	 * a CALL/JMP instruction with 32-bit displacement
	 */
	X86_64_RELOC_BRANCH,
	/**
	 * a MOVQ load of a GOT entry
	 */
	X86_64_RELOC_GOT_LOAD,
	/**
	 * other GOT references
	 */
	X86_64_RELOC_GOT,
	/**
	 * must be followed by a X86_64_RELOC_UNSIGNED
	 */
	X86_64_RELOC_SUBTRACTOR,
	/**
	 * for signed 32-bit displacement with a -1 addend
	 */
	X86_64_RELOC_SIGNED_1,
	/**
	 * for signed 32-bit displacement with a -2 addend
	 */
	X86_64_RELOC_SIGNED_2,
	/**
	 * for signed 32-bit displacement with a -4 addend
	 */
	X86_64_RELOC_SIGNED_4,
	/**
	 * for thread local variables
	 */
	X86_64_RELOC_TLV
}
