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
package ghidra.app.util.bin.format.coff.relocation;

import ghidra.app.util.bin.format.RelocationException;
import ghidra.app.util.bin.format.coff.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.RelocationResult;

public class PowerPC_CoffRelocationHandler implements CoffRelocationHandler {

	@Override
	public boolean canRelocate(CoffFileHeader fileHeader) {
		return fileHeader.getMachine() == CoffMachineType.IMAGE_FILE_MACHINE_POWERPC;
	}

	@Override
	public RelocationResult relocate(Address address, CoffRelocation relocation,
			CoffRelocationContext relocationContext)
			throws MemoryAccessException, RelocationException {

		switch (relocation.getType()) {

			// We are choosing to ignore these types:
			case IMAGE_REL_PPC_ABSOLUTE:
			case IMAGE_REL_PPC_SECTION:
			case IMAGE_REL_PPC_SECREL:
			case IMAGE_REL_PPC_TOKEN: {
				return RelocationResult.SKIPPED;
			}

			// We haven't implemented these types yet:
			case IMAGE_REL_PPC_ADDR32:
			case IMAGE_REL_PPC_ADDR32NB:
			case IMAGE_REL_PPC_ADDR64:
			case IMAGE_REL_PPC_ADDR24:
			case IMAGE_REL_PPC_ADDR16:
			case IMAGE_REL_PPC_ADDR14:
			case IMAGE_REL_PPC_REL24:
			case IMAGE_REL_PPC_REL14:
			case IMAGE_REL_PPC_SECREL16:
			case IMAGE_REL_PPC_REFHI:
			case IMAGE_REL_PPC_REFLO:
			case IMAGE_REL_PPC_PAIR:
			case IMAGE_REL_PPC_SECRELLO:
			case IMAGE_REL_PPC_GPREL:
			default: {
				return RelocationResult.UNSUPPORTED;
			}
		}
	}

	/**
	 * The relocation is ignored.
	 */
	public final static short IMAGE_REL_PPC_ABSOLUTE = 0x0000;

	/**
	 * The 64-bit VA of the target.
	 */
	public final static short IMAGE_REL_PPC_ADDR64 = 0x0001;

	/**
	 * The 32-bit VA of the target.
	 */
	public final static short IMAGE_REL_PPC_ADDR32 = 0x0002;

	/**
	 * The low 24 bits of the VA of the target.
	 * This is valid only when the target symbol is absolute and can be sign-extended to its 
	 * original value.
	 */
	public final static short IMAGE_REL_PPC_ADDR24 = 0x0003;

	/**
	 * The low 16 bits of the target's VA.
	 */
	public final static short IMAGE_REL_PPC_ADDR16 = 0x0004;

	/**
	 * The low 14 bits of the target's VA.
	 * This is valid only when the target symbol is absolute and can be sign-extended to its original value.
	 */
	public final static short IMAGE_REL_PPC_ADDR14 = 0x0005;

	/**
	 * A 24-bit PC-relative offset to the symbol's location.
	 */
	public final static short IMAGE_REL_PPC_REL24 = 0x0006;

	/**
	 * A 14-bit PC-relative offset to the symbol's location.
	 */
	public final static short IMAGE_REL_PPC_REL14 = 0x0007;

	/**
	 * The 32-bit RVA of the target.
	 */
	public final static short IMAGE_REL_PPC_ADDR32NB = 0x000A;

	/**
	 * The 32-bit offset of the target from the beginning of its section.
	 * This is used to support debugging information and static thread local storage.
	 */
	public final static short IMAGE_REL_PPC_SECREL = 0x000B;

	/**
	 * The 16-bit section index of the section that contains the target.
	 * This is used to support debugging information.
	 */
	public final static short IMAGE_REL_PPC_SECTION = 0x000C;

	/**
	 * The 16-bit offset of the target from the beginning of its section.
	 * This is used to support debugging information and static thread local storage.
	 */
	public final static short IMAGE_REL_PPC_SECREL16 = 0x000F;

	/**
	 * The high 16 bits of the target's 32-bit VA. This is used for the first instruction in a 
	 * two-instruction sequence that loads a full address. This relocation must be immediately 
	 * followed by a PAIR relocation whose SymbolTableIndex contains a signed 16-bit displacement 
	 * that is added to the upper 16 bits that was taken from the location that is being relocated.
	 */
	public final static short IMAGE_REL_PPC_REFHI = 0x0010;

	/**
	 * The low 16 bits of the target's VA.
	 */
	public final static short IMAGE_REL_PPC_REFLO = 0x0011;

	/**
	 * A relocation that is valid only when it immediately follows a REFHI or SECRELHI relocation.
	 * Its SymbolTableIndex contains a displacement and not an index into the symbol table.
	 */
	public final static short IMAGE_REL_PPC_PAIR = 0x0012;

	/**
	 * The low 16 bits of the 32-bit offset of the target from the beginning of its section.
	 */
	public final static short IMAGE_REL_PPC_SECRELLO = 0x0013;

	/**
	 * The 16-bit signed displacement of the target relative to the GP register.
	 */
	public final static short IMAGE_REL_PPC_GPREL = 0x0015;

	/**
	 * The CLR token.
	 */
	public final static short IMAGE_REL_PPC_TOKEN = 0x0016;
}
