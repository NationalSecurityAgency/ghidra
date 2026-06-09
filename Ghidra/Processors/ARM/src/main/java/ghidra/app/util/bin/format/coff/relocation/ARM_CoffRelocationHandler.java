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
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;

public class ARM_CoffRelocationHandler implements CoffRelocationHandler {

	/**
	 * The relocation is ignored.
	 */
	public final static short IMAGE_REL_ARM_ABSOLUTE = 0x0000;

	/**
	 * 32-bit VA of target
	 */
	public final static short IMAGE_REL_ARM_ADDR32 = 0x0001;

	/**
	 * 32-bit RVA of target
	 */
	public final static short IMAGE_REL_ARM_ADDR32NB = 0x0002;

	/**
	 * 24-bit relative displacement to target
	 */
	public static final short IMAGE_REL_ARM_BRANCH24 = 0x0003;

	/**
	 * Reference to subroutine call.  Two 16-bit instructions with 11-bit offsets.
	 */
	public static final short IMAGE_REL_ARM_BRANCH11 = 0x0004;

	/**
	 * 32-bit relative address from byte following relocation
	 */
	public static final short IMAGE_REL_ARM_REL32 = 0x000a;

	/**
	 * 16-bit section index of section containing target (for debugging)
	 */
	public static final short IMAGE_REL_ARM_SECTION = 0x000e;

	/**
	 * 32-it offset of target from beginning of sections.  For debugging
	 * and static TLS
	 */
	public static final short IMAGE_REL_ARM_SECREL = 0x000f;

	/**
	 * 32-bit VA of target (MOVW for low 16 bits; MOVT for high 16 bits)
	 */
	public static final short IMAGE_REL_ARM_MOV32 = 0x0010;

	/**
	 * 32-bit VA of target (MOVW for low 16 bits; MOVT for high 16 bits)
	 */
	public static final short IMAGE_REL_THUMB_MOV32 = 0x0011;

	/**
	 * Instruction fixed up with 21-bit relative displace to target 
	 * (which is 2-byte aligned).
	 */
	public static final short IMAGE_REL_THUMB_BRANCH20 = 0x0012;

	// 0x0013 unused

	/**
	 * Instruction fixed up with 25-bit relative displacement to target
	 * (which is 2-byte aligned)
	 */
	public static final short IMAGE_REL_THUMB_BRANCH24 = 0x0014;

	/**
	 * Instruction fixed up with the 25-bit relative displacement to target
	 * (which is 4-byte aligned)
	 */
	public static final short IMAGE_REL_THUMB_BLX23 = 0x0015;

	public static final short IMAGE_REL_ARM_PAIR = 0x0016;

	@Override
	public boolean canRelocate(CoffFileHeader fileHeader) {
		switch (fileHeader.getMachine()) {
			case CoffMachineType.IMAGE_FILE_MACHINE_ARM:
			case CoffMachineType.IMAGE_FILE_MACHINE_ARMNT:
				return true;
			default:
				return false;
		}
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

			case IMAGE_REL_ARM_ABSOLUTE:
				return RelocationResult.SKIPPED;

			case IMAGE_REL_ARM_ADDR32:
				mem.setInt(address, (int) symbolAddr.getOffset());
				break;

			case IMAGE_REL_ARM_ADDR32NB:
				mem.setInt(address, (int) symbolAddr.getOffset());
				break;

			case IMAGE_REL_THUMB_MOV32:
				int symAddress = (int) symbolAddr.getOffset();
				long highImmed16 = getImmed16(symAddress >> 16);
				long lowImmed16 = getImmed16(symAddress & 0xffff);
				long longBytesToAdjust = mem.getLong(address);
				longBytesToAdjust = longBytesToAdjust | (highImmed16 << 32) | lowImmed16;
				byteLength = 8;
				mem.setLong(address, longBytesToAdjust);
				break;

			case IMAGE_REL_THUMB_BRANCH24:
				int displacement = (int) symbolAddr.subtract(address) - 4;
				int adjustment = getThAddr24(displacement);
				bytesToAdjust = bytesToAdjust & 0xd000f800;
				int adjusted = bytesToAdjust | adjustment;
				mem.setInt(address, adjusted);
				break;

			case IMAGE_REL_THUMB_BLX23:
				displacement = (int) symbolAddr.subtract(address) - 4;
				adjustment = getThAddr24(displacement);
				bytesToAdjust = bytesToAdjust & 0xd000f800;
				adjusted = bytesToAdjust | adjustment;
				mem.setInt(address, adjusted);
				break;

			default: {
				return RelocationResult.UNSUPPORTED;
			}
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

	private int getImmed16(int value) {
		// see Immed16 constructor in ARMTHUMBinstructions.sinc
		int immed12_imm8 = value & 0xff;
		int immed12_imm3 = (value >> 8) & 0x7;
		int immed12_i = (value >> 11) & 1;
		int sop003 = (value >> 12) & 0xf;
		return (immed12_imm3 << 28) | (immed12_imm8 << 16) | (immed12_i << 10) | sop003;
	}

	private int getThAddr24(int displacement) {
		// see ThAddr25 constructors in ARMThumbinstructions.sinc
		int part2J1 = (displacement & (1 << 23)) >> 23;
		int part2J2 = (displacement & (1 << 22)) >> 22;
		int part2off = (displacement & (0x7ff << 1)) >> 1;
		int offset10 = (displacement & (0x3ff << 12)) >> 12;
		int offset10s = displacement < 0 ? 1 : 0;
		if (displacement >= 0) {
			part2J1 ^= 1;
			part2J2 ^= 1;
		}
		int adjustment =
			(part2J1 << (16 + 13)) | (part2J2 << (16 + 11)) | (part2off << 16) |
				(offset10s << 10) | offset10;
		return adjustment;
	}



}
