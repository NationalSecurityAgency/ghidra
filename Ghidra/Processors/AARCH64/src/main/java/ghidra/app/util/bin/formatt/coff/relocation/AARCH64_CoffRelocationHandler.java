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
package ghidra.app.util.bin.formatt.coff.relocation;

import ghidra.app.util.bin.format.RelocationException;
import ghidra.app.util.bin.format.coff.*;
import ghidra.app.util.bin.format.coff.relocation.CoffRelocationContext;
import ghidra.app.util.bin.format.coff.relocation.CoffRelocationHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;

public class AARCH64_CoffRelocationHandler implements CoffRelocationHandler {

	/**
	 * Relocation is ignored
	 */
	public static final short IMAGE_REL_ARM64_ABSOLUTE = 0x0000;

	/**
	 * Target's 32-bit VA
	 */
	public static final short IMAGE_REL_ARM64_ADDR32 = 0x0001;


	/**
	 * Target's 32-bit RVA
	 */
	public static final short IMAGE_REL_ARM64_ADDR32NB = 0x0002;

	/**
	 * 26-bit relative displacement to target (for b and bl instructions)
	 */
	public static final short IMAGE_REL_ARM64_BRANCH26 = 0x0003;

	/**
	 * Page base of target (for adrp instruction)
	 */
	public static final short IMAGE_REL_ARM64_PAGEBASE_REL21 = 0x0004;


	/**
	 * 12-bit relative displacement to target (for adr instruction)
	 */
	public static final short IMAGE_REL_ARM64_REL21 = 0x0005;

	/**
	 * 12-bit page offset of target (for add/adds(immed) with shift of 0)
	 */
	public static final short IMAGE_REL_ARM64_PAGEOFFSET_12A = 0x0006;

	/**
	 * 12-bit page offset of target for (ldr indexed, unsigned immediate)
	 */
	public static final short IMAGE_REL_ARM64_PAGEOFFSET_12L = 0x0007;

	/**
	 * 32-bit offset of target from beginning of its section (for debugging and static tls)
	 */
	public static final short IMAGE_REL_ARM64_SECREL = 0x0008;

	/**
	 * bits 0:11 of target's section offset (for add/adds (immed) with shift of 0)
	 */
	public static final short IMAGE_REL_ARM64_SECREL_LOW12A = 0x0009;

	/**
	 * bits 12:23 of target's section offset (for add/adds (immed) with shift of 0)
	 */
	public static final short IMAGE_REL_ARM64_SECREL_HIGH12A = 0x000A;

	/**
	 * bits 0:11 of target's section offset (for ldr, indexed, unsigned immediate)
	 */
	public static final short IMAGE_REL_ARM64_SECREL_LOW12L = 0x000B;

	/**
	 * clr token
	 */
	public static final short IMAGE_REL_ARM64_TOKEN = 0x000C;

	/**
	 * 16-bit section index of target's section (for debugging)
	 */
	public static final short IMAGE_REL_ARM64_SECTION = 0x000D;

	/**
	 * 64-bit VA of target
	 */
	public static final short IMAGE_REL_ARM64_ADDR64 = 0x000E;

	/**
	 * 19-bit offset to target (for conditional b instruction)
	 */
	public static final short IMAGE_REL_ARM64_BRANCH19 = 0x000F;

	/**
	 * 14-bit offset to target (for tbz and tbnz instructions)
	 */
	public static final short IMAGE_REL_ARM64_BRANCH14 = 0x0010;

	/**
	 * 32-bit relative address from byte following relocation
	 */
	public static final short IMAGE_REL_ARM64_REL32 = 0x0011;

	@Override
	public boolean canRelocate(CoffFileHeader fileHeader) {
		return fileHeader.getMachine() == CoffMachineType.IMAGE_FILE_MACHINE_ARM64;
	}

	@Override
	public RelocationResult relocate(Address address, CoffRelocation relocation,
			CoffRelocationContext relocationContext)
			throws MemoryAccessException, RelocationException {

		Program program = relocationContext.getProgram();
		Memory mem = program.getMemory();

		int byteLength = 4; // most relocations affect 4-bytes (change if different)

		int bytesToAdjust = mem.getInt(address);
		Address symbolAddr = relocationContext.getSymbolAddress(relocation);
		switch (relocation.getType()) {

			case IMAGE_REL_ARM64_ABSOLUTE:
				return RelocationResult.SKIPPED;

			case IMAGE_REL_ARM64_ADDR32NB:
				mem.setInt(address, (int) symbolAddr.getOffset());
				break;

			case IMAGE_REL_ARM64_BRANCH26:
				int instMask = 0xfc000000;
				bytesToAdjust = bytesToAdjust & instMask;
				int displacement = (int) symbolAddr.subtract(address);
				displacement >>= 2;
				displacement &= (~instMask);
				bytesToAdjust = bytesToAdjust | displacement;
				mem.setInt(address, bytesToAdjust);
				break;

			case IMAGE_REL_ARM64_PAGEBASE_REL21:
				long base = address.getOffset() & ~0xfff;
				long offset = symbolAddr.getOffset() - base;
				offset = offset >> 12;
				int immlo = (int) offset & 0x3;
				offset = offset >> 2;
				int immhi = (int) offset & 0x7ffff;
				instMask = ~((0x3 << 29) | (0x7ffff << 5));
				bytesToAdjust &= instMask;
				bytesToAdjust = bytesToAdjust | (immhi << 5) | (immlo << 29);
				mem.setInt(address, bytesToAdjust);
				break;

			case IMAGE_REL_ARM64_PAGEOFFSET_12A:
				offset = symbolAddr.getOffset() & 0xfff;
				instMask = ~(0xfff << 10);
				bytesToAdjust &= instMask;
				bytesToAdjust = (int) (bytesToAdjust | (offset << 10));
				mem.setInt(address, bytesToAdjust);
				break;

			case IMAGE_REL_ARM64_PAGEOFFSET_12L:
				int size = bytesToAdjust >>> 30;
				offset = symbolAddr.getOffset() & 0xfff;
				offset >>= size;
				instMask = ~(0xfff << 10);
				bytesToAdjust &= instMask;
				bytesToAdjust = (int) (bytesToAdjust | (offset << 10));
				mem.setInt(address, bytesToAdjust);
				break;

			default: {
				return RelocationResult.UNSUPPORTED;
			}
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

}
