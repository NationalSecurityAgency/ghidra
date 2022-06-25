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
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.NotFoundException;

public class X86_32_CoffRelocationHandler implements CoffRelocationHandler {

	@Override
	public boolean canRelocate(CoffFileHeader fileHeader) {
		return fileHeader.getMachine() == CoffMachineType.IMAGE_FILE_MACHINE_I386;
	}

	@Override
	public void relocate(Address address, CoffRelocation relocation,
			CoffRelocationContext relocationContext)
			throws MemoryAccessException, NotFoundException, RelocationException {

		Program program = relocationContext.getProgram();
		Memory mem = program.getMemory();
		
		int addend = mem.getInt(address);

		switch (relocation.getType()) {

			// We are implementing these types:
			case IMAGE_REL_I386_DIR32: {
				int value = (int) relocationContext.getSymbolAddress(relocation)
						.add(addend)
						.getOffset();
				program.getMemory().setInt(address, value);
				break;
			}
			case IMAGE_REL_I386_DIR32NB: {
				int value = (int) relocationContext.getSymbolAddress(relocation)
						.add(addend)
						.subtract(program.getImageBase());
				mem.setInt(address, value);
				break;
			}
			case IMAGE_REL_I386_REL32: {
				int value = (int) relocationContext.getSymbolAddress(relocation)
						.add(addend)
						.subtract(address);
				value -= 4;
				mem.setInt(address, value);
				break;
			}

			// We are choosing to ignore these types:
			case IMAGE_REL_I386_ABSOLUTE:
			case IMAGE_REL_I386_SECTION:
			case IMAGE_REL_I386_SECREL:
			case IMAGE_REL_I386_TOKEN: {
				break;
			}

			// We haven't implemented these types yet:
			case IMAGE_REL_I386_DIR16:
			case IMAGE_REL_I386_REL16:
			case IMAGE_REL_I386_SEG12:
			case IMAGE_REL_I386_SECREL7:
			default: {
				throw new NotFoundException();
			}
		}
	}

	/**
	 * The relocation is ignored.
	 */
	public final static short IMAGE_REL_I386_ABSOLUTE = 0x0000;

	/**
	 * Not supported.
	 */
	public final static short IMAGE_REL_I386_DIR16 = 0x0001;

	/**
	 * Not supported.
	 */
	public final static short IMAGE_REL_I386_REL16 = 0x0002;

	/**
	 * The target's 32-bit VA.
	 */
	public final static short IMAGE_REL_I386_DIR32 = 0x0006;

	/**
	 * The target's 32-bit RVA.
	 */
	public final static short IMAGE_REL_I386_DIR32NB = 0x0007;

	/**
	 * Not supported.
	 */
	public final static short IMAGE_REL_I386_SEG12 = 0x0009;

	/**
	 * The 16-bit section index of the section that contains the target. 
	 * This is used to support debugging information.
	 */
	public final static short IMAGE_REL_I386_SECTION = 0x000a;

	/**
	 * The 32-bit offset of the target from the beginning of its section. 
	 * This is used to support debugging information and static thread local storage.
	 */
	public final static short IMAGE_REL_I386_SECREL = 0x000b;

	/**
	 * The CLR token.
	 */
	public final static short IMAGE_REL_I386_TOKEN = 0x000c;

	/**
	 * A 7-bit offset from the base of the section that contains the target.
	 */
	public final static short IMAGE_REL_I386_SECREL7 = 0x000d;

	/**
	 * The 32-bit relative displacement to the target. 
	 * This supports the x86 relative branch and call instructions.
	 */
	public final static short IMAGE_REL_I386_REL32 = 0x0014;
}
