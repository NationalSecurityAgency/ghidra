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
package ghidra.app.util.bin.format.elf.relocation;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;

public class Hexagon_ElfRelocationHandler
		extends AbstractElfRelocationHandler<Hexagon_ElfRelocationType, ElfRelocationContext<?>> {

	/**
	 * Constructor
	 */
	public Hexagon_ElfRelocationHandler() {
		super(Hexagon_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_HEXAGON;
	}

	@Override
	public int getRelrRelocationType() {
		return Hexagon_ElfRelocationType.R_HEXAGON_RELATIVE.typeId;
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> elfRelocationContext,
			ElfRelocation relocation, Hexagon_ElfRelocationType type, Address relocationAddress,
			ElfSymbol elfSymbol, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();
		MessageLog log = elfRelocationContext.getLog();

		long addend = relocation.getAddend();
		long offset = (int) relocationAddress.getOffset();
		
		int symbolIndex = relocation.getSymbolIndex();

		int byteLength = 4; // applied relocation length

		// Handle relative relocations that do not require symbolAddr or symbolValue 
		switch (type) {

			case R_HEXAGON_RELATIVE:
				long imageBaseAdjustment = elfRelocationContext.getImageBaseWordAdjustmentOffset();
				int value = (int) (addend + imageBaseAdjustment);
				memory.setInt(relocationAddress, value);
				return new RelocationResult(Status.APPLIED, byteLength);
				
			case R_HEXAGON_COPY:
				markAsUnsupportedCopy(program, relocationAddress, type, symbolName, symbolIndex,
					elfSymbol.getSize(), elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
			
			default:
				break;
		}
		
		// Check for unresolved symbolAddr and symbolValue required by remaining relocation types handled below
		if (handleUnresolvedSymbol(elfRelocationContext, relocation, relocationAddress)) {
			return RelocationResult.FAILURE;
		}	

		int value = (int) (symbolValue + addend);
		int memValue = memory.getInt(relocationAddress);

		switch (type) {
			case R_HEXAGON_B22_PCREL:
				int dist =
					(int) (Integer.toUnsignedLong(value) - Integer.toUnsignedLong((int) offset));
				if ((dist < -0x00800000) || (dist >= 0x00800000)) {
					return RelocationResult.FAILURE;
				}
				memValue &= ~0x01ff3fff;
				memValue |= 0x00003fff & dist;
				memValue |= 0x01ff0000 & (dist << 2);
				memory.setInt(relocationAddress, memValue);
				break;

//				break;
//			case R_HEXAGON_B15_PCREL:
//				break;
//			case R_HEXAGON_B7_PCREL:
//				break;

			case R_HEXAGON_HI16:
				value = (value >> 16) & 0xffff;
				/* fallthrough */
			case R_HEXAGON_LO16:
				memValue &= ~0x00c03fff;
				memValue |= value & 0x3fff;
				memValue |= (value & 0xc000) << 8;
				memory.setInt(relocationAddress, memValue);
				break;

			case R_HEXAGON_32:
				memory.setInt(relocationAddress, value);
				if (symbolIndex != 0 && addend != 0 && !elfSymbol.isSection()) {
					warnExternalOffsetRelocation(program, relocationAddress, symbolAddr, symbolName,
						addend, elfRelocationContext.getLog());
					applyComponentOffsetPointer(program, relocationAddress, addend);
				}
				break;

			case R_HEXAGON_16:
				memory.setShort(relocationAddress, (short) value);
				byteLength = 2;
				break;

			case R_HEXAGON_8:
				memory.setByte(relocationAddress, (byte) value);
				byteLength = 1;
				break;

//			case R_HEXAGON_GPREL16_0:
//				break;
//			case R_HEXAGON_GPREL16_1:
//				break;
//			case R_HEXAGON_GPREL16_2:
//				break;
//			case R_HEXAGON_GPREL16_3:
//				break;
//			case R_HEXAGON_HL16:
//				break;
//			case R_HEXAGON_B13_PCREL:
//				break;
//			case R_HEXAGON_B9_PCREL:
//				break;
//			case R_HEXAGON_B32_PCREL_X:
//				break;
//			case R_HEXAGON_32_6_X:
//				break;
//			case R_HEXAGON_B22_PCREL_X:
//				break;
//			case R_HEXAGON_B15_PCREL_X:
//				break;
//			case R_HEXAGON_B13_PCREL_X:
//				break;
//			case R_HEXAGON_B9_PCREL_X:
//				break;
//			case R_HEXAGON_B7_PCREL_X:
//				break;
//			case R_HEXAGON_16_X:
//				break;
//			case R_HEXAGON_12_X:
//				break;
//			case R_HEXAGON_11_X:
//				break;
//			case R_HEXAGON_10_X:
//				break;
//			case R_HEXAGON_9_X:
//				break;
//			case R_HEXAGON_8_X:
//				break;
//			case R_HEXAGON_7_X:
//				break;
//			case R_HEXAGON_6_X:
//				break;

			case R_HEXAGON_32_PCREL:
				dist = (int) (Integer.toUnsignedLong(value) - Integer.toUnsignedLong((int) offset));
				memory.setInt(relocationAddress, dist);
				break;

			case R_HEXAGON_GLOB_DAT:
			case R_HEXAGON_JMP_SLOT: {
				memory.setInt(relocationAddress, value);
				break;
			}

//			case R_HEXAGON_PLT_B22_PCREL:
//				break;
//			case R_HEXAGON_GOTOFF_LO16:
//				break;
//			case R_HEXAGON_GOTOFF_HI16:
//				break;
//			case R_HEXAGON_GOTOFF_32:
//				break;
//			case R_HEXAGON_GOT_LO16:
//				break; // TODO: See MIPS for similar HI/LO approach
//			case R_HEXAGON_GOT_HI16:
//				break; // TODO: See MIPS for similar HI/LO approach
//			case R_HEXAGON_GOT_32:
//				break;
//			case R_HEXAGON_GOT_16:
//				break;

			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, log);
				return RelocationResult.UNSUPPORTED;
		}

		return new RelocationResult(Status.APPLIED, byteLength);
	}

}
