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

import ghidra.app.util.bin.format.coff.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.NotFoundException;

public class X86_64_CoffRelocationHandler extends CoffRelocationHandler {

	@Override
	public boolean canRelocate(CoffFileHeader fileHeader) {
		return fileHeader.getMachine() == CoffMachineType.IMAGE_FILE_MACHINE_AMD64;
	}

	@Override
	public void relocate(Program program, Address address, Symbol symbol,
			CoffRelocation relocation) throws MemoryAccessException, NotFoundException {

		int distance = 0;
		long addend = program.getMemory().getInt(address);

		switch (relocation.getType()) {

			// We are implementing these types:
			case IMAGE_REL_AMD64_ADDR64:
				addend = program.getMemory().getLong(address); // overwrite default 4-byte addend
				program.getMemory().setLong(address, symbol.getAddress().add(addend).getOffset());
				break;
			case IMAGE_REL_AMD64_ADDR32:
				program.getMemory().setInt(address,
					(int) symbol.getAddress().add(addend).getOffset());
				break;
			case IMAGE_REL_AMD64_ADDR32NB: {
				program.getMemory().setInt(address,
					(int) symbol.getAddress().add(addend).subtract(program.getImageBase()));
				break;
			}
			case IMAGE_REL_AMD64_REL32_5: { // fallthrough to IMAGE_REL_AMD64_REL32 to get correct 'distance'
				distance++;
			}
			case IMAGE_REL_AMD64_REL32_4: { // fallthrough to IMAGE_REL_AMD64_REL32 to get correct 'distance'
				distance++;
			}
			case IMAGE_REL_AMD64_REL32_3: { // fallthrough to IMAGE_REL_AMD64_REL32 to get correct 'distance'
				distance++;
			}
			case IMAGE_REL_AMD64_REL32_2: { // fallthrough to IMAGE_REL_AMD64_REL32 to get correct 'distance'
				distance++;
			}
			case IMAGE_REL_AMD64_REL32_1: { // fallthrough to IMAGE_REL_AMD64_REL32 to get correct 'distance'
				distance++;
			}
			case IMAGE_REL_AMD64_REL32: {
				program.getMemory().setInt(address,
					(int) symbol.getAddress().add(addend).subtract(address) - 4 - distance);
				break;
			}

			// We are choosing to ignore these types:
			case IMAGE_REL_AMD64_ABSOLUTE:
			case IMAGE_REL_AMD64_SECTION:
			case IMAGE_REL_AMD64_SECREL:
			case IMAGE_REL_AMD64_TOKEN: {
				break;
			}

			// We haven't implemented these types yet:
			case IMAGE_REL_AMD64_SECREL7:
			case IMAGE_REL_AMD64_SREL32:
			case IMAGE_REL_AMD64_PAIR:
			case IMAGE_REL_AMD64_SSPAN32:
			default: {
				throw new NotFoundException();
			}
		}
	}

	/**
	 * The relocation is ignored.
	 */
	public final static short IMAGE_REL_AMD64_ABSOLUTE = 0x0000;

	/**
	 * The 64-bit VA of the relocation target.
	 */
	public final static short IMAGE_REL_AMD64_ADDR64 = 0x0001;

	/**
	 * The 32-bit VA of the relocation target.
	 */
	public final static short IMAGE_REL_AMD64_ADDR32 = 0x0002;

	/**
	 * The 32-bit address without an image base (RVA).
	 */
	public final static short IMAGE_REL_AMD64_ADDR32NB = 0x0003;

	/**
	 * The 32-bit relative address from the byte following the relocation.
	 */
	public final static short IMAGE_REL_AMD64_REL32 = 0x0004;

	/**
	 * The 32-bit address relative to byte distance 1 from the relocation.
	 */
	public final static short IMAGE_REL_AMD64_REL32_1 = 0x0005;

	/**
	 * The 32-bit address relative to byte distance 2 from the relocation.
	 */
	public final static short IMAGE_REL_AMD64_REL32_2 = 0x0006;

	/**
	 * The 32-bit address relative to byte distance 3 from the relocation.
	 */
	public final static short IMAGE_REL_AMD64_REL32_3 = 0x0007;

	/**
	 * The 32-bit address relative to byte distance 4 from the relocation.
	 */
	public final static short IMAGE_REL_AMD64_REL32_4 = 0x0008;

	/**
	 * The 32-bit address relative to byte distance 5 from the relocation.
	 */
	public final static short IMAGE_REL_AMD64_REL32_5 = 0x0009;

	/**
	 * The 16-bit section index of the section that contains the target. 
	 * This is used to support debugging information.
	 */
	public final static short IMAGE_REL_AMD64_SECTION = 0x000a;

	/**
	 * The 32-bit offset of the target from the beginning of its section. 
	 * This is used to support debugging information and static thread local storage.
	 */
	public final static short IMAGE_REL_AMD64_SECREL = 0x000b;

	/**
	 * A 7-bit unsigned offset from the base of the section that contains the target.
	 */
	public final static short IMAGE_REL_AMD64_SECREL7 = 0x000c;

	/**
	 * CLR tokens.
	 */
	public final static short IMAGE_REL_AMD64_TOKEN = 0x000d;

	/**
	 * A 32-bit signed span-dependent value emitted into the object.
	 */
	public final static short IMAGE_REL_AMD64_SREL32 = 0x000e;

	/**
	 * A pair that must immediately follow every span-dependent value.
	 */
	public final static short IMAGE_REL_AMD64_PAIR = 0x000f;

	/**
	 * A 32-bit signed span-dependent value that is applied at link time.
	 */
	public final static short IMAGE_REL_AMD64_SSPAN32 = 0x0010;
}
