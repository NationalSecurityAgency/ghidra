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
 * {@link X86_64_MachoRelocationHandler} constants
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/x86_64/reloc.h.auto.html">mach-o/x86_64/reloc.h</a> 
 */
public class X86_64_MachoRelocationConstants {
	
	/**
	 * For absolute addresses
	 */
	public final static int X86_64_RELOC_UNSIGNED = 0;

	/**
	 * For signed 32-bit displacement
	 */
	public final static int X86_64_RELOC_SIGNED = 1;

	/**
	 *  A CALL/JMP instruction with 32-bit displacement
	 */
	public final static int X86_64_RELOC_BRANCH = 2;

	/**
	 * A MOVQ load of a GOT entry
	 */
	public final static int X86_64_RELOC_GOT_LOAD = 3;

	/**
	 * Other GOT references
	 */
	public final static int X86_64_RELOC_GOT = 4;

	/**
	 * Must be followed by a X86_64_RELOC_UNSIGNED
	 */
	public final static int X86_64_RELOC_SUBTRACTOR = 5;

	/**
	 * For signed 32-bit displacement with a -1 addend
	 */
	public final static int X86_64_RELOC_SIGNED_1 = 6;

	/**
	 * For signed 32-bit displacement with a -2 addend
	 */
	public final static int X86_64_RELOC_SIGNED_2 = 7;

	/**
	 * For signed 32-bit displacement with a -4 addend
	 */
	public final static int X86_64_RELOC_SIGNED_4 = 8;

	/**
	 * For thread local variables
	 */
	public final static int X86_64_RELOC_TLV = 9;
}
