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

import java.util.Optional;
import java.util.stream.Stream;

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
	
	/*
	 * Is the given Hexagon sub-instruction a Duplex instruction 
	 */
	private boolean isDuplex(long ins) {
		return ((ins >>> 14) & 0b11) == 0b00;
	}
	
	/*
	 * Spread the bits of a value to be relocated based on a mask representing the positions containing the bits of that value.
	 */
	private int applyMask(int mask, int val) {
		int res = 0;
		int off = 0;
		for(int i = 0; i < 32; i++) {
			int valBit = (val >> off) & 1;
			// If mask[n] is set, fill with next bit from val
			if (((mask >> i) & 1) != 0) {
				res |= (valBit << i);
				off++;
			}
			
		}
		return res;
	}
	
	/* 
	 * Find the mask for R_HEX_8_X type relocations
	 */
	private int findMaskR8(int ins) {
		if (isDuplex(ins)) {
			return 0x03F00000;
		}
		switch (ins & 0xFF000000) {
		case 0xDE000000:
			return 0x00E020E8;
		case 0x3C000000:
			return 0x0000207F;
		default:
			return 0x00001FE0;
		}
	}
	
	/* 
	 * Find the mask for R_HEX_11_X type relocations
	 */
	private int findMaskR11(int ins) {
		if (isDuplex(ins)) {
			return 0x03F00000;
		}
		switch (ins & 0xFF000000) {
		case 0xA1000000:
			return 0x060020FF;
		default:
			return 0x06003FE0;
		}
	}
	
	private record InstructionMask(int compareMask, int valueMask) {}
	
	private InstructionMask r6Masks[] = new InstructionMask[] {
		new InstructionMask(0x38000000, 0x0000201f),
		new InstructionMask(0x39000000, 0x0000201f),
		new InstructionMask(0x3e000000, 0x00001f80),
		new InstructionMask(0x3f000000, 0x00001f80),
		new InstructionMask(0x40000000, 0x000020f8),
		new InstructionMask(0x41000000, 0x000007e0),
		new InstructionMask(0x42000000, 0x000020f8),
		new InstructionMask(0x43000000, 0x000007e0),
		new InstructionMask(0x44000000, 0x000020f8),
		new InstructionMask(0x45000000, 0x000007e0),
		new InstructionMask(0x46000000, 0x000020f8),
		new InstructionMask(0x47000000, 0x000007e0),
		new InstructionMask(0x6a000000, 0x00001f80),
		new InstructionMask(0x7c000000, 0x001f2000),
		new InstructionMask(0x9a000000, 0x00000f60),
		new InstructionMask(0x9b000000, 0x00000f60),
		new InstructionMask(0x9c000000, 0x00000f60),
		new InstructionMask(0x9d000000, 0x00000f60),
		new InstructionMask(0x9f000000, 0x001f0100),
		new InstructionMask(0xab000000, 0x0000003f),
		new InstructionMask(0xad000000, 0x0000003f),
		new InstructionMask(0xaf000000, 0x00030078),
		new InstructionMask(0xd7000000, 0x006020e0),
		new InstructionMask(0xd8000000, 0x006020e0),
		new InstructionMask(0xdb000000, 0x006020e0),
		new InstructionMask(0xdf000000, 0x006020e0),
	};
	
	private Optional<Integer> findMaskR6Common(int ins) {
		return Stream.of(r6Masks)
				.filter(i -> i.compareMask() == (ins & 0xFF000000))
				.map(i -> i.valueMask())
				.findAny();
	}
	
	/* 
	 * Find the mask for R_HEX_6_X type relocations
	 */
	private Optional<Integer> findMaskR6(int ins) {
		if (isDuplex(ins)) {
			return Optional.of(0x03F00000);
		}
		return findMaskR6Common(ins);
	}
	
	/* 
	 * Find the mask for R_HEX_16_X type relocations
	 */
	private Optional<Integer> findMaskR16(int ins) {
		if (isDuplex(ins)) {
			return Optional.of(0x03F00000);
		}
		int maskedIns = ins & ~(0b11 << 14);
		
		switch((0xff000000 & maskedIns)) {
		case 0x48000000:
			return Optional.of(0x061f20ff);
		case 0x49000000:
			return Optional.of(0x061f3fe0);
		case 0x78000000:
			return Optional.of(0x00df3fe0);
		case 0xb0000000:
			return Optional.of(0x0fe03fe0);
		}
		switch((0xff802000 & maskedIns)) {
		case 0x74000000:
		case 0x74002000:
		case 0x74800000:
		case 0x74802000:
			return Optional.of(0x00001fe0);
		}
		  
		  return findMaskR6Common(maskedIns);
	}
	
	/* 
	 * Find the mask for R_HEX_GPREL16_* type relocations
	 */
	private Optional<Integer> findMaskGpRelative(int ins) {
		
		if((ins & 0xF9E00000) == 0x48000000) {
			return Optional.of(0x061F20FF);
		}
		if((ins & 0xF9E01800) == 0x48A00000) {
			return Optional.of(0x061F20FF);
		}
		if((ins & 0xF9E00000) == 0x49000000) {
			return Optional.of(0x061F3FE0);
		}
		if((ins & 0xF9E00000) == 0x49200000) {
			return Optional.of(0x061F3FE0);
		}
		return Optional.empty();
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
		int pcRelativeValue = (int) (Integer.toUnsignedLong(value) - Integer.toUnsignedLong((int) offset));
		int memValue = memory.getInt(relocationAddress);

		switch (type) {
			case R_HEXAGON_B22_PCREL:
				if ((pcRelativeValue < -0x00800000) || (pcRelativeValue >= 0x00800000)) {
					return RelocationResult.FAILURE;
				}
				memValue &= ~0x01ff3ffe;
				int dist = pcRelativeValue >>> 2;
				memValue |= 0x00003ffe & (dist << 1);
				memValue |= 0x01ff0000 & (dist << 3);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_B15_PCREL:
				int mask = 0x00DF20FE;
				memValue |= applyMask(mask, pcRelativeValue >> 2);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_B7_PCREL:
				mask = 0x00001F18;
				memValue |= applyMask(mask, pcRelativeValue >> 2);
				memory.setInt(relocationAddress, memValue);
				break;

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

			case R_HEXAGON_GPREL16_0:
				Optional<Integer> gpMask = findMaskGpRelative(memValue);
				if(gpMask.isEmpty()) {
					markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, log);
					return RelocationResult.UNSUPPORTED;
				}
				mask = gpMask.get();
				memValue |= applyMask(mask, value);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_GPREL16_1:
				value >>>= 1;
				if(
					// Rd=memh(gp+#u16:1)
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b1010)) ||
					// Rd=memuh(gp+#u16:1)
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b1011))
				) {
					memValue &= ~0x61F3FE0;
					memValue |= (value & 0x1FF) << 5;
					memValue |= ((value >> 9) & 0x1F) << 16;
					memValue |= ((value >> 14) & 0x3) << 25;
					memory.setInt(relocationAddress, memValue);
				} else if (
					// memh(gp+#u16:1)=Rt
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b0010)) ||
					// memh(gp+#u16:1)=Rt.H
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b0011)) ||
					// memh(gp+#u16:1)=Nt.new
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b0101) && (((memValue >> 11) & 0b11) == 0b01))
				) {
					memValue &= ~0x61f20ff;
					memValue |= (value & 0xFF);
					memValue |= ((value >> 8) & 1) << 13;
					memValue |= ((value >> 9) & 0x1F) << 16;
					memValue |= ((value >> 14) & 0x3) << 25;
					memory.setInt(relocationAddress, memValue);
				}
				else {
					markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, log);
					return RelocationResult.UNSUPPORTED;
				}
				break;
			case R_HEXAGON_GPREL16_2:
				value >>>= 2;
				if(
					// Rd=memw(gp+#u16:2)
					(((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b1100)
				) {
					memValue &= ~0x61F3FE0;
					memValue |= (value & 0x1FF) << 5;
					memValue |= ((value >> 9) & 0x1F) << 16;
					memValue |= ((value >> 14) & 0x3) << 25;
					memory.setInt(relocationAddress, memValue);
				} else if (
					// memw(gp+#u16:2)=Rt
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b0100)) ||
					// memw(gp+#u16:2)=Nt.new
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b0101) && (((memValue >> 11) & 0b11) == 0b10))
				) {
					memValue &= ~0x61f20ff;
					memValue |= (value & 0xFF);
					memValue |= ((value >> 8) & 1) << 13;
					memValue |= ((value >> 9) & 0x1F) << 16;
					memValue |= ((value >> 14) & 0x3) << 25;
					memory.setInt(relocationAddress, memValue);
				}
				else {
					markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, log);
					return RelocationResult.UNSUPPORTED;
				}
				break;
			case R_HEXAGON_GPREL16_3:
				value >>>= 3;
				if(
					// Rdd=memd(gp+#u16:3)
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b1110))
				) {
					memValue &= ~0x61F3FE0;
					memValue |= (value & 0x1FF) << 5;
					memValue |= ((value >> 9) & 0x1F) << 16;
					memValue |= ((value >> 14) & 0x3) << 25;
					memory.setInt(relocationAddress, memValue);
				} else {
					markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, log);
					return RelocationResult.UNSUPPORTED;
				}
				break;
//			case R_HEXAGON_HL16:
//				break;
			case R_HEXAGON_B13_PCREL:
				mask = 0x00202FFE;
				memValue |= applyMask(mask, pcRelativeValue >> 2);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_B9_PCREL:
				mask = 0x003000FE;
				memValue |= applyMask(mask, pcRelativeValue >> 2);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_B32_PCREL_X:
				// (S + A - P) >> 6
				dist = pcRelativeValue >>> 6;
				memValue &= ~0x0fff3fff;
				memValue |= dist & 0x3fff;
				dist = dist >>> 14;
				memValue |= ((dist & 0xFFF) << 16);
				memory.setInt(relocationAddress, memValue);
				byteLength = 4;
				break;
			case R_HEXAGON_32_6_X:
				// This relocation is used to handle extended immediate values
				int c = (value >>> 6);
				memValue &= ~0x0fff3fff;
				memValue |= (c & 0x3FFF);
				memValue |= ((c >> 14) & 0xFFF) << 16;
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_B22_PCREL_X:
				mask = 0x01FF3FFE;
				memValue |= applyMask(mask, pcRelativeValue & 0x3F);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_B15_PCREL_X:
				mask = 0x00DF20FE;
				memValue |= applyMask(mask, pcRelativeValue & 0x3F);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_B13_PCREL_X:
				mask = 0x00202FFE;
				memValue |= applyMask(mask, pcRelativeValue & 0x3F);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_B9_PCREL_X:
				mask = 0x003000FE;
				memValue |= applyMask(mask, pcRelativeValue & 0x3F);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_B7_PCREL_X:
				mask = 0x00001F18;
				memValue |= applyMask(mask, pcRelativeValue & 0x3F);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_16_X:
				Optional<Integer> r6Mask = findMaskR16(memValue);
				if(r6Mask.isEmpty()) {
					markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, log);
					return RelocationResult.UNSUPPORTED;
				}
				mask = r6Mask.get();
				memValue |= applyMask(mask, value & 0x3F);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_12_X:
				mask = 0x000F1FE0;
				memValue |= applyMask(mask, value & 0x3F);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_11_X:
				mask = findMaskR11(memValue);
				memValue |= applyMask(mask, value & 0x3F);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_10_X:
				mask = 0x0020EFE0;
				memValue |= applyMask(mask, value & 0x3F);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_9_X:
				mask = 0x00003FE0;
				memValue |= applyMask(mask, value  & 0x3F);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_8_X:
				mask = findMaskR8(memValue);
				memValue |= applyMask(mask, value & 0x3F);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_7_X:
				mask = 0x00000FE0;
				memValue |= applyMask(mask, value & 0x3F);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_6_X:
				r6Mask = findMaskR6(memValue);
				if(r6Mask.isEmpty()) {
					markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, log);
					return RelocationResult.UNSUPPORTED;
				}
				mask = r6Mask.get();
				memValue |= applyMask(mask, value & 0x3F);
				memory.setInt(relocationAddress, memValue);
				break;
			case R_HEXAGON_32_PCREL:
				memory.setInt(relocationAddress, pcRelativeValue);
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
			case R_HEXAGON_6_PCREL_X:
				int opcode = memValue >> 16;
				// bitmap depends on instruction opcode
				if (opcode == 0x6a49) { // add Rd5,PacketPC,Uimm32_0712x
					dist = pcRelativeValue & 0x3f;
					memValue &= ~(0x3f << 7);
					memValue |= (dist << 7);
					memory.setInt(relocationAddress, memValue);
					break;
				} // otherwise fall through
			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, log);
				return RelocationResult.UNSUPPORTED;
		}

		return new RelocationResult(Status.APPLIED, byteLength);
	}

}
