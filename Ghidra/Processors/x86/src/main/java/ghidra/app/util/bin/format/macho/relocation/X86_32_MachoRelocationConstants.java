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
 * {@link X86_32_MachoRelocationHandler} constants
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/reloc.h.auto.html">mach-o/reloc.h</a> 
 */
public class X86_32_MachoRelocationConstants {

	/**
	 * Generic relocation
	 */
	public final static int GENERIC_RELOC_VANILLA = 0;

	/**
	 * Only follows a GENERIC_RELOC_SECTDIFF
	 */
	public final static int GENERIC_RELOC_PAIR = 1;

	/**
	 * The difference of two symbols defined in two different sections
	 */
	public final static int GENERIC_RELOC_SECTDIFF = 2;

	/**
	 * Pre-bound lazy pointer
	 */
	public final static int GENERIC_RELOC_PB_LA_PTR = 3;

	/**
	 * The difference of two symbols defined in two different sections
	 */
	public final static int GENERIC_RELOC_LOCAL_SECTDIFF = 4;

	/**
	 * Thread local variables
	 */
	public final static int GENERIC_RELOC_TLV = 5;
}
