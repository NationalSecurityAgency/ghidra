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
import ghidra.util.Msg;

public class MIPS_CoffRelocationHandler implements CoffRelocationHandler {

	// REFHI consumes the following PAIR relocation in mips.c.  Ghidra calls
	// relocate() once per relocation, so retain the REFHI state until PAIR.
	private Address pendingRefHiAddress;
	private long pendingRefHiTarget;

	private record SymbolResolution(boolean found, int target) {}

	@Override
	public boolean canRelocate(CoffFileHeader fileHeader) {
		return fileHeader.getMachine() == CoffMachineType.IMAGE_FILE_MACHINE_R3000 ||
			fileHeader.getMachine() == CoffMachineType.IMAGE_FILE_MACHINE_R4000;
	}

	@Override
	public RelocationResult relocate(Address address, CoffRelocation relocation,
			CoffRelocationContext relocationContext)
			throws MemoryAccessException, RelocationException {

		Program program = relocationContext.getProgram();
		Memory mem = program.getMemory();
		short reloct = relocation.getType();

		switch (reloct) {
			case IMAGE_REL_MIPS_ABSOLUTE:
				// mips.c: Ignore (fixup not required).
				return RelocationResult.SKIPPED;

			case IMAGE_REL_MIPS_REFHALF: {
				// mips.c: *(SHORT UNALIGNED *)pb += (SHORT)(rvaBase >> 16);
				short value = mem.getShort(address);
				SymbolResolution result = resolveSymbol(address.getOffset(), relocation,
					relocationContext, reloct, value);
				if (!result.found) {
					return RelocationResult.FAILURE;
				}
				value = (short) (value + (short) (result.target >> 16));
				mem.setShort(address, value);
				return new RelocationResult(Status.APPLIED, 2);
			}

			case IMAGE_REL_MIPS_REFWORD: {
				// mips.c: *(LONG UNALIGNED *)pb += rvaBase;
				int value = mem.getInt(address);
				SymbolResolution result = resolveSymbol(address.getOffset(), relocation,
					relocationContext, reloct, value);
				if (!result.found) {
					return RelocationResult.FAILURE;
				}
				value += result.target;
				mem.setInt(address, value);
				return new RelocationResult(Status.APPLIED, 4);
			}

			case IMAGE_REL_MIPS_REFWORDNB: { // TODO: check if resolveSymbol is appropiated here
				Address symbolAddress;
				try {
					symbolAddress = relocationContext.getSymbolAddress(relocation);
				}
				catch (RelocationException e) {
					symbolAddress = null;
					Msg.debug(this,
						"%s @ 0x%x Symbol not found for index 0x%x".formatted(
							getRelocationTypeName(reloct), address.getOffset(),
							relocation.getSymbolIndex()));
				}
				if (symbolAddress == null) {
					return RelocationResult.SKIPPED;
				}

				/*
				 * mips.c adds the symbol RVA, not its VA.  Ghidra's symbol
				 * address is the relocated VA, so remove the program image base.
				 */
				long rva = symbolAddress.getOffset() - program.getImageBase().getOffset();

				int value = mem.getInt(address);
				value += (int) rva;
				mem.setInt(address, value);
				return new RelocationResult(Status.APPLIED, 4);
			}

			case IMAGE_REL_MIPS_SECREL: { // TODO: check if resolveSymbol is appropiated here
				Address symbolAddress;
				try {
					symbolAddress = relocationContext.getSymbolAddress(relocation);
				}
				catch (RelocationException e) {
					symbolAddress = null;
					Msg.debug(this,
						"%s @ 0x%x Symbol not found for index 0x%x".formatted(
							getRelocationTypeName(reloct), address.getOffset(),
							relocation.getSymbolIndex()));
				}
				if (symbolAddress == null) {
					return RelocationResult.SKIPPED;
				}

				/*
				 * mips.c:
				 *
				 *   psec = PsecFindSectionOfRVA(rva, pimage);
				 *   rva -= psec->rva;
				 *   *(LONG *)pb += rva;
				 *
				 * The corresponding Ghidra value is the offset from the
				 * memory block containing the symbol.
				 */
				long sectionOffset = symbolAddress.getOffset();
				var block = mem.getBlock(symbolAddress);
				if (block != null) {
					sectionOffset -= block.getStart().getOffset();
				}

				int value = mem.getInt(address);
				value += (int) sectionOffset;
				mem.setInt(address, value);
				return new RelocationResult(Status.APPLIED, 4);
			}

			case IMAGE_REL_MIPS_REFHI: {
				/*
				 * mips.c requires REFHI to be followed by PAIR:
				 *
				 *   ltemp = signed16(REFHI) << 16;
				 *   ltemp += signed16(PAIR.SymbolTableIndex);
				 *   ltemp += rva;
				 *   ltemp += ImageBase;
				 *   ltemp += 0x8000;
				 *   REFHI = ltemp >> 16;
				 *
				 * Ghidra's symbol address is already the relocated VA
				 * (rva + ImageBase), so store that value and finish when
				 * PAIR is processed.
				 */
				pendingRefHiAddress = address;
				SymbolResolution result = resolveSymbol(address.getOffset(), relocation,
					relocationContext, reloct, mem.getShort(address));
				if (!result.found) {
					return RelocationResult.FAILURE;
				}
				pendingRefHiTarget = result.target;
				return new RelocationResult(Status.APPLIED, 2);
			}

			case IMAGE_REL_MIPS_PAIR: {
				if (pendingRefHiAddress == null) {
					// mips.c warns for an unmatched PAIR and does not modify it.
					Msg.warn(this, "Unmatched " + getRelocationTypeName(reloct));
					return RelocationResult.SKIPPED;
				}

				/*
				 * PAIR.SymbolTableIndex is a signed 16-bit displacement,
				 * not a symbol-table index.
				 */
				short pairAddend = (short) relocation.getSymbolIndex();
				short refHi = mem.getShort(pendingRefHiAddress);

				long value = ((long) refHi << 16);
				value += pairAddend;
				value += pendingRefHiTarget;
				value += 0x8000;

				mem.setShort(pendingRefHiAddress, (short) (value >> 16));

				pendingRefHiAddress = null;
				pendingRefHiTarget = 0;

				// PAIR has no data bytes of its own.
				return new RelocationResult(Status.APPLIED, 0);
			}

			case IMAGE_REL_MIPS_REFLO: {
				// mips.c: *(SHORT UNALIGNED *)pb += (SHORT)rvaBase;
				short value = mem.getShort(address);
				SymbolResolution result = resolveSymbol(address.getOffset(), relocation,
					relocationContext, reloct, value);
				if (!result.found) {
					return RelocationResult.FAILURE;
				}
				value = (short) (value + ((short) result.target));
				mem.setShort(address, value);
				return new RelocationResult(Status.APPLIED, 2);
			}

			case IMAGE_REL_MIPS_JMPADDR: {
				/*
				 * mips.c:
				 *
				 *   value = (value & 0x03ffffff) +
				 *           ((rvaBase >> 2) & 0x03ffffff);
				 *   value |= original & 0xfc000000;
				 */
				int current = mem.getInt(address);
				SymbolResolution result = resolveSymbol(address.getOffset(), relocation,
					relocationContext, reloct, (current & 0x03ffffff) << 2);
				if (!result.found) {
					return RelocationResult.FAILURE;
				}
				int value = (current & 0xfc000000) |
					(((current & 0x03ffffff) + (result.target >> 2) & 0x03ffffff) & 0x03ffffff);
				mem.setInt(address, value);
				return new RelocationResult(Status.APPLIED, 4);
			}

			case IMAGE_REL_MIPS_SECTION:
				/*
				 * mips.c adds the target COFF section number. The current
				 * CoffRelocationContext API does not expose the symbol's
				 * COFF section number, so do not replace this with an
				 * incorrect generic value.
				 */
			case IMAGE_REL_MIPS_GPREL:
			case IMAGE_REL_MIPS_LITERAL:
				/*
				 * mips.c requires pGpExtern and computes:
				 *
				 *   Offset = rva + existingSigned16 - GP
				 *
				 * The current Ghidra COFF relocation context does not expose
				 * the linker GP symbol, so these cannot be implemented
				 * correctly as ordinary low-16 relocations.
				 */
			default:
				return RelocationResult.UNSUPPORTED;
		}
	}

	/*
	 * Symbol resolution with fail safe to handle sections as symbols
	 */
	private SymbolResolution resolveSymbol(long addressOffset, CoffRelocation relocation,
			CoffRelocationContext relocationContext, short reloct, long inMemory) {
		CoffFileHeader header = relocationContext.getHeader();
		int target = 0;
		try {
			Address symbolAddress;
			symbolAddress = relocationContext.getSymbolAddress(relocation);
			target = (int) symbolAddress.getOffset();
		}
		catch (RelocationException e) {
			long idx = relocation.getSymbolIndex();
			String symbolName = header.getSymbolAtIndex(idx).getName();
			CoffSectionHeader section = header.getSections()
					.stream()
					.filter(c -> c.getName().equals(symbolName))
					.findFirst()
					.orElse(null);
			if (section != null) {
				int va = section.getPhysicalAddress(); // In the Object file, physical address is used. If this ends up beguin and executable then ????
				target = va;
				//Msg.info(this, "%s @ 0x%x Symbol %s using 0x%x to 0x%x".formatted(
				//	getRelocationTypeName(reloct), addressOffset, symbolName, va, inMemory));

			}
			else {
				Msg.debug(this, "%s @ 0x%x Symbol %s not found for index 0x%x"
						.formatted(getRelocationTypeName(reloct), addressOffset, symbolName, idx));
				return new SymbolResolution(false, 0);
			}
		}
		return new SymbolResolution(true, target);
	}

	/**
	 * {@return a human-readable names matching SzMipsRelocationType() in mips.c}
	 */
	private String getRelocationTypeName(short relocType) {
		return switch (relocType) {
			case IMAGE_REL_MIPS_ABSOLUTE -> "ABS";
			case IMAGE_REL_MIPS_PAIR -> "PAIR";
			case IMAGE_REL_MIPS_REFHALF -> "REFHALF";
			case IMAGE_REL_MIPS_REFWORD -> "REFWORD";
			case IMAGE_REL_MIPS_REFWORDNB -> "REFWORDNB";
			case IMAGE_REL_MIPS_JMPADDR -> "JMPADDR";
			case IMAGE_REL_MIPS_REFHI -> "REFHI";
			case IMAGE_REL_MIPS_REFLO -> "REFLO";
			case IMAGE_REL_MIPS_GPREL -> "GPREL";
			case IMAGE_REL_MIPS_LITERAL -> "LITERAL";
			case IMAGE_REL_MIPS_SECTION -> "SECTION";
			case IMAGE_REL_MIPS_SECREL -> "SECREL";
			default -> "<UNKNOWN>";
		};
	}

	public static final short IMAGE_REL_MIPS_ABSOLUTE = 0x0000;
	public static final short IMAGE_REL_MIPS_REFHALF = 0x0001;
	public static final short IMAGE_REL_MIPS_REFWORD = 0x0002;
	public static final short IMAGE_REL_MIPS_JMPADDR = 0x0003;
	public static final short IMAGE_REL_MIPS_REFHI = 0x0004;
	public static final short IMAGE_REL_MIPS_REFLO = 0x0005;
	public static final short IMAGE_REL_MIPS_GPREL = 0x0006;
	public static final short IMAGE_REL_MIPS_LITERAL = 0x0007;
	public static final short IMAGE_REL_MIPS_SECTION = 0x000A;
	public static final short IMAGE_REL_MIPS_SECREL = 0x000B;
	public static final short IMAGE_REL_MIPS_SECRELLO = 0x000C;
	public static final short IMAGE_REL_MIPS_SECRELHI = 0x000D;
	public static final short IMAGE_REL_MIPS_JMPADDR16 = 0x0010;
	public static final short IMAGE_REL_MIPS_REFWORDNB = 0x0022;
	public static final short IMAGE_REL_MIPS_PAIR = 0x0025;
}
