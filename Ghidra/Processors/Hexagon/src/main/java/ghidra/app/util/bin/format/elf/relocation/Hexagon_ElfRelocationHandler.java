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
				memValue &= ~0x01ff3ffe;
				dist = dist >>> 2;
				memValue |= 0x00003ffe & (dist << 1);
				memValue |= 0x01ff0000 & (dist << 3);
				memory.setInt(relocationAddress, memValue);
				break;
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

			case R_HEXAGON_GPREL16_0:
				if(
					// Rd=memb(gp+#u16:0)
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b1000)) ||
					// Rd=memub(gp+#u16:0)
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b1001))
				) {
					memValue &= ~0x61F3FE0;
					memValue |= (value & 0x1FF) << 5;
					memValue |= ((value >> 9) & 0x1F) << 16;
					memValue |= ((value >> 14) & 0x3) << 25;
					memory.setInt(relocationAddress, memValue);
				} else if (
					// memb(gp+#u16:0)=Rt
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b0000)) ||
					// memb(gp+#u16:0)=Nt.new
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b0101) && (((memValue >> 11) & 0b11) == 0b00))
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
//			case R_HEXAGON_B13_PCREL:
//				break;
//			case R_HEXAGON_B9_PCREL:
//				break;
			case R_HEXAGON_B32_PCREL_X:
				// (S + A - P) >> 6
				dist = (int) (Integer.toUnsignedLong(value) - Integer.toUnsignedLong((int) offset));
				dist = dist >>> 6;
				memValue &= ~0x0fff3fff;
				memValue |= dist & 0x3fff;
				dist = dist >>> 14;
				memValue |= ((dist & 0xFFF) << 16);
				memory.setInt(relocationAddress, memValue);
				byteLength = 4;
				break;
			case R_HEXAGON_32_6_X:
				// This relocation is used to handle extended immediates
				int c = (value >>> 6);
				memValue &= ~0x0fff3fff;
				memValue |= (c & 0x3FFF);
				memValue |= ((c >> 14) & 0xFFF) << 16;
				memory.setInt(relocationAddress, memValue);
				break;
//			case R_HEXAGON_B22_PCREL_X:
//				break;
			case R_HEXAGON_B15_PCREL_X:
				dist = (int) (Integer.toUnsignedLong(value) - Integer.toUnsignedLong((int) offset)) & 0x3f;
				dist >>>= 6;
				if(
					// if(pu) call #r15:2
					((((memValue >> 24) & 0b11111111) == 0b01011101) && (((memValue >> 21) & 1) == 0) && (((memValue >> 11) & 1) == 0)) ||
					// if(!pu) call #r15:2
					((((memValue >> 24) & 0b11111111) == 0b01011101) && (((memValue >> 21) & 1) == 1) && (((memValue >> 11) & 1) == 0))
				) {
					memValue &= ~0xDF20FE;
					memValue |= (dist & 0x7F) << 1;
					memValue |= ((dist >> 7) & 1) << 13;
					memValue |= ((dist >> 8) & 0x1F) << 16;
					memValue |= ((dist >> 13) & 0x3) << 22;
					memory.setInt(relocationAddress, memValue);
				} else {
					markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, log);
					return RelocationResult.UNSUPPORTED;
				}
				break;
//			case R_HEXAGON_B13_PCREL_X:
//				break;
			case R_HEXAGON_B9_PCREL_X:
				dist = (int) (Integer.toUnsignedLong(value) - Integer.toUnsignedLong((int) offset)) & 0x3F;
				if(
					// Rd=u6 ; jump #r9:2
					(((memValue >> 24) & 0b11111111) == 0b00010110) ||
					// Rd=Rs ; jump #r9:2
					(((memValue >> 24) & 0b11111111) == 0b00010111)
				) {
					memValue &= ~0x3000FE;
					memValue |= (dist & 0x7F) << 1;
					memValue |= ((dist >> 7) & 0x3) << 20;
					memory.setInt(relocationAddress, memValue);
				} else {
					markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, log);
					return RelocationResult.UNSUPPORTED;
				}
				break;
//			case R_HEXAGON_B7_PCREL_X:
//				break;
			case R_HEXAGON_16_X:
				//Rd=#s16
				if(((memValue >> 24) & 0b11111111) == 0b01111000) {
					memValue &= ~0xDF3FF0;
					memValue |= (value & 0x1FF) << 5;
					memValue |= ((value >> 9) & 0x1F) << 16;
					memValue |= ((value >> 14) & 0x3) << 22;
					memory.setInt(relocationAddress, memValue);
				} else if (
					// Rd=memb(gp+#u16:0)
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b1000)) ||
					// Rd=memh(gp+#u16:1)
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b1010)) ||
					// Rd=memw(gp+#u16:2)
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b1100)) ||
					// Rdd=memd(gp+#u16:3)
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b1110)) ||
					// Rd=memub(gp+#u16:0)
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b1001)) ||
					// Rd=memuh(gp+#u16:1)
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b1011))
				) {
					memValue &= ~0x61F3F70;
					memValue |= (value & 0x1FF) << 5;
					memValue |= ((value >> 9) & 0x1F) << 16;
					memValue |= ((value >> 14) & 0x3) << 25;
					memory.setInt(relocationAddress, memValue);
				} else if (
					// memb(gp+#u16:0)=Rt
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b0000)) ||
					// memh(gp+#u16:1)=Rt
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b0010)) ||
					// memh(gp+#u16:1)=Rt.h
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b0011)) ||
					// memw(gp+#u16:2)=Rt
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b0100)) ||
					// memd(gp+#u16:3)=Rtt
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b0110))
				) {
					memValue &= ~0x61f20ff;
					memValue |= (value & 0xFF);
					memValue |= ((value >> 8) & 1) << 13;
					memValue |= ((value >> 9) & 0x1F) << 16;
					memValue |= ((value >> 14) & 0x3) << 25;
					memory.setInt(relocationAddress, memValue);
				} else if (
					// memb(gp+#u16:0)=Nt.new
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b0101) && (((memValue >> 11) & 0b11) == 0b00)) ||
					// memh(gp+#u16:1)=Nt.new
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b0101) && (((memValue >> 11) & 0b11) == 0b01)) ||
					// memw(gp+#u16:2)=Nt.new
					((((memValue >> 27) & 0b11111) == 0b01001) && (((memValue >> 21) & 0b1111) == 0b0101) && (((memValue >> 11) & 0b11) == 0b10))
				) {
					memValue &= ~0x61f20ff;
					memValue |= (value & 0xFF);
					memValue |= ((value >> 8) & 1) << 13;
					memValue |= ((value >> 9) & 0x1F) << 16;
					memValue |= ((value >> 14) & 0x3) << 25;
					memory.setInt(relocationAddress, memValue);
				} else {
					markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, log);
					return RelocationResult.UNSUPPORTED;
				}
				break;
			case R_HEXAGON_12_X:
				if(
					// if(pu) Rd=#s12
					((((memValue >> 23) & 0b111111111) == 0b011111100) && (((memValue >> 20) & 1) == 0) && (((memValue >> 13) & 1) == 0)) ||
					// if(pu.new) Rd=#s12
					((((memValue >> 23) & 0b111111111) == 0b011111100) && (((memValue >> 20) & 1) == 0) && (((memValue >> 13) & 1) == 1)) ||
					// if(!pu) Rd=#s12
					((((memValue >> 23) & 0b111111111) == 0b011111101) && (((memValue >> 20) & 1) == 0) && (((memValue >> 13) & 1) == 0)) ||
					// if(pu.new) Rd=#s12
					((((memValue >> 23) & 0b111111111) == 0b011111101) && (((memValue >> 20) & 1) == 0) && (((memValue >> 13) & 1) == 1))
				) {
					memValue &= ~0xF1FE0;
					memValue |= (value & 0xFF) << 5;
					memValue |= ((value >> 8) & 0xF) << 16;
					memory.setInt(relocationAddress, memValue);
				} else {
					markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, log);
					return RelocationResult.UNSUPPORTED;
				}
				break;
//			case R_HEXAGON_11_X:
//				break;
//			case R_HEXAGON_10_X:
//				break;
//			case R_HEXAGON_9_X:
//				break;
			case R_HEXAGON_8_X:
				if(
					// Rdd=combine(Rs, #s8)
					((((memValue >> 24) & 0b11111111) == 0b01110011) && (((memValue >> 21) & 0b11) == 0b00) && (((memValue >> 13) & 1) == 1)) ||
					// Rdd=combine(#s8, Rs)
					((((memValue >> 24) & 0b11111111) == 0b01110011) && (((memValue >> 21) & 0b11) == 0b01) && (((memValue >> 13) & 1) == 1))
				) {
					memValue &= ~0x1FE0;
					memValue |= (value & 0xFF) << 5;
					memory.setInt(relocationAddress, memValue);
				} else if (
					// Rdd=combine(#s8, #S8)
					(((memValue >> 23) & 0b111111111) == 0b011111000)
				) {
					memValue &= ~0x7F2000;
					memValue |= (value & 1) << 13;
					memValue |= ((value >> 1) & 0x7F) << 16;
					memory.setInt(relocationAddress, memValue);
				} else if (
					// memb(Rs+#u6:0)=#S8
					((((memValue >> 25) & 0b01111111) == 0b0011110) && (((memValue >> 21) & 0b11) == 0b00)) ||
					// memh(Rs+#u6:1)=#S8
					((((memValue >> 25) & 0b01111111) == 0b0011110) && (((memValue >> 21) & 0b11) == 0b01)) ||
					// memw(Rs+#u6:2)=#S8
					((((memValue >> 25) & 0b01111111) == 0b0011110) && (((memValue >> 21) & 0b11) == 0b10))
				) {
					memValue &= ~0x207F;
					memValue |= (value & 0x7F);
					memValue |= ((value >> 7) & 1) << 13;
					memory.setInt(relocationAddress, memValue);
				} else if (
					// Rx=add(#u8,asl(Rx,#u5))
					(((((memValue >> 24) & 0b11111111) == 0b11011110) && (((memValue >> 4) & 1) == 0) && ((memValue >> 1) & 0b11) == 0b10)) ||
					// Rx=sub(#u8,asl(Rx,#u5))
					(((((memValue >> 24) & 0b11111111) == 0b11011110) && (((memValue >> 4) & 1) == 0) && ((memValue >> 1) & 0b11) == 0b11)) ||
					// Rx=add(#u8,lsr(Rx,#u5))
					(((((memValue >> 24) & 0b11111111) == 0b11011110) && (((memValue >> 4) & 1) == 1) && ((memValue >> 1) & 0b11) == 0b10)) ||
					// Rx=sub(#u8,lsr(Rx,#u5))
					(((((memValue >> 24) & 0b11111111) == 0b11011110) && (((memValue >> 4) & 1) == 1) && ((memValue >> 1) & 0b11) == 0b11))
				) {
					memValue &= ~0xE020E8;
					memValue |= (value & 1) << 3;
					memValue |= ((value >> 1) & 0x7) << 6;
					memValue |= ((value >> 4) & 1) << 13;
					memValue |= ((value >> 5) & 0x7) << 21;
					memory.setInt(relocationAddress, memValue);
				} else if (
					// Rd=mux(Pu,Rs,#s8)
					((((memValue >> 23) & 0b111111111) == 0b011100110) && (((memValue >> 13) & 1) == 0)) ||
					// Rd=mux(Pu,#s8,Rs)
					((((memValue >> 23) & 0b111111111) == 0b011100111) && (((memValue >> 13) & 1) == 0))
				) {
					memValue &= ~0x1FE0;
					memValue |= (value & 0xFF) << 5;
					memory.setInt(relocationAddress, memValue);
				} else {
					markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, log);
					return RelocationResult.UNSUPPORTED;
				}
				break;
//			case R_HEXAGON_7_X:
//				break;
			case R_HEXAGON_6_X:
				// duplex
				if(((memValue >> 14) & 0b11) == 0b00) {
					int low = (memValue & 0x1FFF);
					int hig = (memValue >> 16) & 0x1FFF;
					int cls = ((memValue >> 13) & 1) | (((memValue >> 29) & 0b111) << 1);
					int parse = (memValue >> 14) & 0x3;
					
					// { A1 ; A1 } | { A1 ; L1 } | { A1 ; L2 } | { A1 ; S1 } | { A1 ; S2 }    
					if ((cls == 0b0011) || (cls == 0b0100) || (cls == 0b0101) || (cls == 0b0110) || (cls == 0b0111)) {
						// D4=#s6
						if(((hig >> 10) & 0b111) == 0b010) {
							hig &= ~0x3F0;
							hig |= (value & 0x3f) << 4;
							memory.setInt(relocationAddress, (((cls >> 1) & 0x3) << 29) | (hig << 16) | (parse << 14) | ((cls & 1) << 13) | low);
						} else {
							markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, log);
							return RelocationResult.UNSUPPORTED;
						}
					
					} else {
						markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, log);
						return RelocationResult.UNSUPPORTED;
					}
				} else if (
					// Rdd=combine(#s8, #U6)
					(((memValue >> 23) & 0b111111111) == 0b011111001)
				) {
					memValue &= ~0x7F2000;
					memValue |= (value & 1) << 13;
					memValue |= ((value >> 1) & 0x1F) << 16;
					memory.setInt(relocationAddress, memValue);
				} else if (
					// Rd=memw(Rt<<#u2+#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011101100) && (((memValue >> 12) & 1) == 1)) ||
					// Rdd=memd(Rt<<#u2+#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011101110) && (((memValue >> 12) & 1) == 1)) ||
					// Rd=memb(Rt<<#u2+#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011101000) && (((memValue >> 12) & 1) == 1)) ||
					// Rd=memub(Rt<<#u2+#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011101001) && (((memValue >> 12) & 1) == 1)) ||
					// Rd=memh(Rt<<#u2+#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011101010) && (((memValue >> 12) & 1) == 1)) ||
					// Rd=memuh(Rt<<#u2+#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011101011) && (((memValue >> 12) & 1) == 1))
				) {
					memValue &= ~0xF60;
					memValue |= (value & 0x3) << 5;
					memValue |= ((value >> 2) & 0xF) << 16;
					memory.setInt(relocationAddress, memValue);
				} else if (
					// memb(Rs+#u6:0)=#S8
					((((memValue >> 25) & 0b01111111) == 0b0011110) && (((memValue >> 21) & 0b11) == 0b00)) ||
					// memh(Rs+#u6:1)=#S8
					((((memValue >> 25) & 0b01111111) == 0b0011110) && (((memValue >> 21) & 0b11) == 0b01)) ||
					// memw(Rs+#u6:2)=#S8
					((((memValue >> 25) & 0b01111111) == 0b0011110) && (((memValue >> 21) & 0b11) == 0b10))
				) {
					memValue &= ~0x1F80;
					memValue |= (value & 0x3F) << 7;
					memory.setInt(relocationAddress, memValue);
				} else if (
					// memb(Ru<<#u2+#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101101000) && (((memValue >> 7) & 1) == 1)) ||
					// memh(Ru<<#u2+#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101101010) && (((memValue >> 7) & 1) == 1)) ||
					// memh(Ru<<#u2+#u6)=Rt.h
					((((memValue >> 21) & 0b11111111111) == 0b10101101011) && (((memValue >> 7) & 1) == 1)) ||
					// memw(Ru<<#u2+#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101101100) && (((memValue >> 7) & 1) == 1)) ||
					// memd(Ru<<#u2+#u6)=Rtt
					((((memValue >> 21) & 0b11111111111) == 0b10101101110) && (((memValue >> 7) & 1) == 1)) ||
					
					// memb(Ru<<#u2+#u6)=Nt.new
					((((memValue >> 21) & 0b11111111111) == 0b10101101101) && (((memValue >> 11) & 0b11) == 0b00) && (((memValue >> 7) & 1) == 1)) ||
					// memh(Ru<<#u2+#u6)=Nt.new
					((((memValue >> 21) & 0b11111111111) == 0b10101101101) && (((memValue >> 11) & 0b11) == 0b01) && (((memValue >> 7) & 1) == 1)) ||
					// memw(Ru<<#u2+#u6)=Nt.new
					((((memValue >> 21) & 0b11111111111) == 0b10101101101) && (((memValue >> 11) & 0b11) == 0b10) && (((memValue >> 7) & 1) == 1))
				) {
					memValue &= ~0x3F;
					memValue |= (value & 0x3F);
					memory.setInt(relocationAddress, memValue);
				} else if (
					// if(pt) Rd=memd(Rs+#u6:3)
					((((memValue >> 21) & 0b11111111111) == 0b01000001110) && (((memValue >> 13) & 1) == 0)) ||
					// if(pt.new) Rd=memd(Rs+#u6:3)
					((((memValue >> 21) & 0b11111111111) == 0b01000011110) && (((memValue >> 13) & 1) == 0)) ||
					// if(!pt) Rd=memd(Rs+#u6:3)
					((((memValue >> 21) & 0b11111111111) == 0b01000101110) && (((memValue >> 13) & 1) == 0)) ||
					// if(!pt.new) Rd=memd(Rs+#u6:3)
					((((memValue >> 21) & 0b11111111111) == 0b01000111110) && (((memValue >> 13) & 1) == 0)) ||
						
					// if(pt) Rd=memw(Rs+#u6:2)
					((((memValue >> 21) & 0b11111111111) == 0b01000001100) && (((memValue >> 13) & 1) == 0)) ||
					// if(pt.new) Rd=memw(Rs+#u6:2)
					((((memValue >> 21) & 0b11111111111) == 0b01000011100) && (((memValue >> 13) & 1) == 0)) ||
					// if(!pt) Rd=memw(Rs+#u6:2)
					((((memValue >> 21) & 0b11111111111) == 0b01000101100) && (((memValue >> 13) & 1) == 0)) ||
					// if(!pt.new) Rd=memw(Rs+#u6:2)
					((((memValue >> 21) & 0b11111111111) == 0b01000111100) && (((memValue >> 13) & 1) == 0)) ||
					
					// if(pt) Rd=memuh(Rs+#u6:1)
					((((memValue >> 21) & 0b11111111111) == 0b01000001011) && (((memValue >> 13) & 1) == 0)) ||
					// if(pt.new) Rd=memuh(Rs+#u6:1)
					((((memValue >> 21) & 0b11111111111) == 0b01000011011) && (((memValue >> 13) & 1) == 0)) ||
					// if(!pt) Rd=memuh(Rs+#u6:1)
					((((memValue >> 21) & 0b11111111111) == 0b01000101011) && (((memValue >> 13) & 1) == 0)) ||
					// if(!pt.new) Rd=memuh(Rs+#u6:1)
					((((memValue >> 21) & 0b11111111111) == 0b01000111011) && (((memValue >> 13) & 1) == 0)) ||
					
					// if(pt) Rd=memh(Rs+#u6:1)
					((((memValue >> 21) & 0b11111111111) == 0b01000001010) && (((memValue >> 13) & 1) == 0)) ||
					// if(pt.new) Rd=memh(Rs+#u6:1)
					((((memValue >> 21) & 0b11111111111) == 0b01000011010) && (((memValue >> 13) & 1) == 0)) ||
					// if(!pt) Rd=memh(Rs+#u6:1)
					((((memValue >> 21) & 0b11111111111) == 0b01000101010) && (((memValue >> 13) & 1) == 0)) ||
					// if(!pt.new) Rd=memh(Rs+#u6:1)
					((((memValue >> 21) & 0b11111111111) == 0b01000111010) && (((memValue >> 13) & 1) == 0)) ||
					
					// if(pt) Rd=memub(Rs+#u6:0)
					((((memValue >> 21) & 0b11111111111) == 0b01000001001) && (((memValue >> 13) & 1) == 0)) ||
					// if(pt.new) Rd=memub(Rs+#u6:0)
					((((memValue >> 21) & 0b11111111111) == 0b01000011001) && (((memValue >> 13) & 1) == 0)) ||
					// if(!pt) Rd=memub(Rs+#u6:0)
					((((memValue >> 21) & 0b11111111111) == 0b01000101001) && (((memValue >> 13) & 1) == 0)) ||
					// if(!pt.new) Rd=memub(Rs+#u6:0)
					((((memValue >> 21) & 0b11111111111) == 0b01000111001) && (((memValue >> 13) & 1) == 0)) ||
					
					// if(pt) Rd=memb(Rs+#u6:0)
					((((memValue >> 21) & 0b11111111111) == 0b01000001000) && (((memValue >> 13) & 1) == 0)) ||
					// if(pt.new) Rd=memb(Rs+#u6:0)
					((((memValue >> 21) & 0b11111111111) == 0b01000011000) && (((memValue >> 13) & 1) == 0)) ||
					// if(!pt) Rd=memb(Rs+#u6:0)
					((((memValue >> 21) & 0b11111111111) == 0b01000101000) && (((memValue >> 13) & 1) == 0)) ||
					// if(!pt.new) Rd=memb(Rs+#u6:0)
					((((memValue >> 21) & 0b11111111111) == 0b01000111000) && (((memValue >> 13) & 1) == 0))
				) {
					memValue &= ~0x7E0;
					memValue |= (value & 0x3F) << 5;
					memory.setInt(relocationAddress, memValue);
				} else if (
					// if(pt) Rd=memd(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111110) && (((memValue >> 11) & 0b111) == 0b100) && (((memValue >> 7) & 1) == 1)) || 
					// if(!pt) Rd=memd(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111110) && (((memValue >> 11) & 0b111) == 0b101) && (((memValue >> 7) & 1) == 1)) ||
					// if(pt.new) Rd=memd(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111110) && (((memValue >> 11) & 0b111) == 0b110) && (((memValue >> 7) & 1) == 1)) ||
					// if(!pt.new) Rd=memd(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111110) && (((memValue >> 11) & 0b111) == 0b111) && (((memValue >> 7) & 1) == 1)) ||
						
					// if(pt) Rd=memw(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111100) && (((memValue >> 11) & 0b111) == 0b100) && (((memValue >> 7) & 1) == 1)) || 
					// if(!pt) Rd=memw(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111100) && (((memValue >> 11) & 0b111) == 0b101) && (((memValue >> 7) & 1) == 1)) ||
					// if(pt.new) Rd=memw(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111100) && (((memValue >> 11) & 0b111) == 0b110) && (((memValue >> 7) & 1) == 1)) ||
					// if(!pt.new) Rd=memw(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111100) && (((memValue >> 11) & 0b111) == 0b111) && (((memValue >> 7) & 1) == 1)) ||
					
					// if(pt) Rd=memh(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111010) && (((memValue >> 11) & 0b111) == 0b100) && (((memValue >> 7) & 1) == 1)) || 
					// if(!pt) Rd=memh(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111010) && (((memValue >> 11) & 0b111) == 0b101) && (((memValue >> 7) & 1) == 1)) ||
					// if(pt.new) Rd=memh(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111010) && (((memValue >> 11) & 0b111) == 0b110) && (((memValue >> 7) & 1) == 1)) ||
					// if(!pt.new) Rd=memh(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111010) && (((memValue >> 11) & 0b111) == 0b111) && (((memValue >> 7) & 1) == 1)) ||
					
					// if(pt) Rd=memuh(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111011) && (((memValue >> 11) & 0b111) == 0b100) && (((memValue >> 7) & 1) == 1)) || 
					// if(!pt) Rd=memuh(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111011) && (((memValue >> 11) & 0b111) == 0b101) && (((memValue >> 7) & 1) == 1)) ||
					// if(pt.new) Rd=memuh(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111011) && (((memValue >> 11) & 0b111) == 0b110) && (((memValue >> 7) & 1) == 1)) ||
					// if(!pt.new) Rd=memuh(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111011) && (((memValue >> 11) & 0b111) == 0b111) && (((memValue >> 7) & 1) == 1)) ||
					
					// if(pt) Rd=memb(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111000) && (((memValue >> 11) & 0b111) == 0b100) && (((memValue >> 7) & 1) == 1)) || 
					// if(!pt) Rd=memb(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111000) && (((memValue >> 11) & 0b111) == 0b101) && (((memValue >> 7) & 1) == 1)) ||
					// if(pt.new) Rd=memb(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111000) && (((memValue >> 11) & 0b111) == 0b110) && (((memValue >> 7) & 1) == 1)) ||
					// if(!pt.new) Rd=memb(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111000) && (((memValue >> 11) & 0b111) == 0b111) && (((memValue >> 7) & 1) == 1)) ||
					
					// if(pt) Rd=memub(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111001) && (((memValue >> 11) & 0b111) == 0b100) && (((memValue >> 7) & 1) == 1)) || 
					// if(!pt) Rd=memub(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111001) && (((memValue >> 11) & 0b111) == 0b101) && (((memValue >> 7) & 1) == 1)) ||
					// if(pt.new) Rd=memub(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111001) && (((memValue >> 11) & 0b111) == 0b110) && (((memValue >> 7) & 1) == 1)) ||
					// if(!pt.new) Rd=memub(#u6)
					((((memValue >> 21) & 0b11111111111) == 0b10011111001) && (((memValue >> 11) & 0b111) == 0b111) && (((memValue >> 7) & 1) == 1))
				) {
					memValue &= ~0x1F100;
					memValue |= (value & 1) << 8;
					memValue |= ((value>>1) & 0x1F) << 16;
					memory.setInt(relocationAddress, memValue);
				} else if (
					// if(pv) memb(#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101111000) && (((memValue >> 13) & 1) == 0) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 0)) ||
					// if(!pv) memb(#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101111000) && (((memValue >> 13) & 1) == 0) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 1)) ||
					// if(pv.new) memb(#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101111000) && (((memValue >> 13) & 1) == 1) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 0)) ||
					// if(!pv.new) memb(#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101111000) && (((memValue >> 13) & 1) == 1) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 1)) ||
					
					// if(pv) memh(#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101111010) && (((memValue >> 13) & 1) == 0) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 0)) ||
					// if(!pv) memh(#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101111010) && (((memValue >> 13) & 1) == 0) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 1)) ||
					// if(pv.new) memh(#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101111010) && (((memValue >> 13) & 1) == 1) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 0)) ||
					// if(!pv.new) memh(#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101111010) && (((memValue >> 13) & 1) == 1) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 1)) ||
					
					// if(pv) memh(#u6)=Rt.H
					((((memValue >> 21) & 0b11111111111) == 0b10101111011) && (((memValue >> 13) & 1) == 0) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 0)) ||
					// if(!pv) memh(#u6)=Rt.H
					((((memValue >> 21) & 0b11111111111) == 0b10101111011) && (((memValue >> 13) & 1) == 0) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 1)) ||
					// if(pv.new) memh(#u6)=Rt.H
					((((memValue >> 21) & 0b11111111111) == 0b10101111011) && (((memValue >> 13) & 1) == 1) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 0)) ||
					// if(!pv.new) memh(#u6)=Rt.H
					((((memValue >> 21) & 0b11111111111) == 0b10101111011) && (((memValue >> 13) & 1) == 1) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 1)) ||
					
					// if(pv) memw(#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101111100) && (((memValue >> 13) & 1) == 0) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 0)) ||
					// if(!pv) memw(#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101111100) && (((memValue >> 13) & 1) == 0) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 1)) ||
					// if(pv.new) memw(#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101111100) && (((memValue >> 13) & 1) == 1) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 0)) ||
					// if(!pv.new) memw(#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101111100) && (((memValue >> 13) & 1) == 1) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 1)) ||
					
					// if(pv) memd(#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101111110) && (((memValue >> 13) & 1) == 0) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 0)) ||
					// if(!pv) memd(#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101111110) && (((memValue >> 13) & 1) == 0) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 1)) ||
					// if(pv.new) memd(#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101111110) && (((memValue >> 13) & 1) == 1) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 0)) ||
					// if(!pv.new) memd(#u6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101111110) && (((memValue >> 13) & 1) == 1) && (((memValue >> 7) & 1) == 1) && (((memValue >> 2) & 1) == 1))
				) {
					memValue &= ~0x30078;
					memValue |= (value & 0xF) << 3;
					memValue |= ((value>>4) & 0x3) << 16;
					memory.setInt(relocationAddress, memValue);
				} else if (
					// Rd=memb(Re=#U6)
					((((memValue >> 21) & 0b11111111111) == 0b10011011000) && (((memValue >> 12) & 0b11) == 0b01)) ||
					// Rd=memub(Re=#U6)
					((((memValue >> 21) & 0b11111111111) == 0b10011011001) && (((memValue >> 12) & 0b11) == 0b01)) ||
					// Rd=memh(Re=#U6)
					((((memValue >> 21) & 0b11111111111) == 0b10011011010) && (((memValue >> 12) & 0b11) == 0b01)) ||
					// Rd=memuh(Re=#U6)
					((((memValue >> 21) & 0b11111111111) == 0b10011011011) && (((memValue >> 12) & 0b11) == 0b01)) ||
					// Rd=memw(Re=#U6)
					((((memValue >> 21) & 0b11111111111) == 0b10011011100) && (((memValue >> 12) & 0b11) == 0b01)) ||
					// Rdd=memd(Re=#U6)
					((((memValue >> 21) & 0b11111111111) == 0b10011011110) && (((memValue >> 12) & 0b11) == 0b01))
				) {
					memValue &= ~0xF60;
					memValue |= (value & 0x3) << 5;
					memValue |= ((value >> 2) & 0xF) << 8;
					memory.setInt(relocationAddress, memValue);
				} else if (
					// memw(Re=#U6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101011100) && (((memValue >> 13) & 1) == 0) && (((memValue >> 7) & 1) == 1)) ||
					// memh(Re=#U6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101011010) && (((memValue >> 13) & 1) == 0) && (((memValue >> 7) & 1) == 1)) ||
					// memh(Re=#U6)=Rt.H
					((((memValue >> 21) & 0b11111111111) == 0b10101011011) && (((memValue >> 13) & 1) == 0) && (((memValue >> 7) & 1) == 1)) ||
					// memb(Re=#U6)=Rt
					((((memValue >> 21) & 0b11111111111) == 0b10101011000) && (((memValue >> 13) & 1) == 0) && (((memValue >> 7) & 1) == 1)) ||
					// memd(Re=#U6)=Rtt
					((((memValue >> 21) & 0b11111111111) == 0b10101011110) && (((memValue >> 13) & 1) == 0) && (((memValue >> 7) & 1) == 1))
				) {
					memValue &= ~0x3F;
					memValue |= (value & 0x3F);
					memory.setInt(relocationAddress, memValue);
				} else if (
					// if(pv) memw(Rs+#u6:2)=#S6
					(((memValue >> 21) & 0b11111111111) == 0b00111000010) ||
					// if(!pv) memw(Rs+#u6:2)=#S6
					(((memValue >> 21) & 0b11111111111) == 0b00111000110) ||
					// if(pv.new) memw(Rs+#u6:2)=#S6
					(((memValue >> 21) & 0b11111111111) == 0b00111001010) ||
					// if(!pv.new) memw(Rs+#u6:2)=#S6
					(((memValue >> 21) & 0b11111111111) == 0b00111001110) ||
					
					// if(pv) memh(Rs+#u6:1)=#S6
					(((memValue >> 21) & 0b11111111111) == 0b00111000001) ||
					// if(!pv) memh(Rs+#u6:1)=#S6
					(((memValue >> 21) & 0b11111111111) == 0b00111000101) ||
					// if(pv.new) memh(Rs+#u6:1)=#S6
					(((memValue >> 21) & 0b11111111111) == 0b00111001001) ||
					// if(!pv.new) memh(Rs+#u6:1)=#S6
					(((memValue >> 21) & 0b11111111111) == 0b00111001101) ||
					
					// if(pv) memb(Rs+#u6:0)=#S6
					(((memValue >> 21) & 0b11111111111) == 0b00111000000) ||
					// if(!pv) memb(Rs+#u6:0)=#S6
					(((memValue >> 21) & 0b11111111111) == 0b00111000100) ||
					// if(pv.new) memb(Rs+#u6:0)=#S6
					(((memValue >> 21) & 0b11111111111) == 0b00111001000) ||
					// if(!pv.new) memb(Rs+#u6:0)=#S6
					(((memValue >> 21) & 0b11111111111) == 0b00111001100)
				) {
					memValue &= ~0x1F80;
					memValue |= (value & 0x3F) << 7;
					memory.setInt(relocationAddress, memValue);
				} else {
					markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, log);
					return RelocationResult.UNSUPPORTED;
				}
				break;

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
			case R_HEXAGON_6_PCREL_X:
				int opcode = memValue >> 16;
				// bitmap depends on instruction opcode
				if (opcode == 0x6a49) { // add Rd5,PacketPC,Uimm32_0712x
					dist = (int) (Integer.toUnsignedLong(value) -
						Integer.toUnsignedLong((int) offset));
					dist = dist & 0x3f;
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
