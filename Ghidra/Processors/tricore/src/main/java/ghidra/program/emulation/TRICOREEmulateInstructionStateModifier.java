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
package ghidra.program.emulation;

import java.math.BigInteger;

import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.callother.OpBehaviorOther;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.Varnode;

public class TRICOREEmulateInstructionStateModifier extends EmulateInstructionStateModifier {
	 Register FCX,PCXI,LCX,PSW,a10,a11,d8,a12,d12;
	
	public TRICOREEmulateInstructionStateModifier(Emulate emu) {
		super(emu);
		
			registerPcodeOpBehavior("saveCallerState", new tricore_SaveCallerState());
			registerPcodeOpBehavior("restoreCallerState", new tricore_RestoreCallerState());			
			cacheRegisters(emu);
	}

	// Save Caller State, could be done in Pcode
	//
	private class tricore_SaveCallerState implements OpBehaviorOther {
		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {
			int numArgs = inputs.length - 1;
			if (numArgs != 3) throw new LowlevelError(this.getClass().getName() + ": requires 3 inputs (FCX, LCX, PCXI), got " + numArgs);

			MemoryState memoryState = emu.getMemoryState();
			
			// compute new EA
			BigInteger FCXvalue = memoryState.getBigInteger(FCX);
			// read the value at FCX, if get nothing, then assume just increment the FCX to get to new node.
			
			// EA = {FCX.FCXS, 6'b0, FCX.FCXO, 6'b0};
			long ea = FCXvalue.longValue();
			ea = ((ea & 0xffff0000) << 12) | ((ea & 0xffff) << 6);
			
			Address EA_addr = emu.getExecuteAddress().getNewAddress(ea);
			AddressSpace addressSpace = emu.getExecuteAddress().getAddressSpace();
			
			// new_FCX = M(EA, word);
			BigInteger new_FCXvalue = memoryState.getBigInteger(addressSpace, ea, 4, false);
			// if new_FCX == 0, or not-initialized, then just increment FCX again
			if (new_FCXvalue.equals(BigInteger.ZERO)) {
				new_FCXvalue = FCXvalue.add(BigInteger.ONE);
			}

			//	M(EA,16 * word) = {PCXI, PSW, A[10], A[11], D[8], D[9], D[10], D[11], A[12], A[13], A[14], A[15], D[12], D[13], D[14], D[15]};
			byte[] outBytes = new byte[4*16];
			int index = 0;
			index += copyRegisterToArray(PCXI, PCXI.getBitLength()/8, memoryState, outBytes, index);
			index += copyRegisterToArray(PSW, PSW.getBitLength()/8, memoryState, outBytes, index);
			index += copyRegisterToArray(a10, 2 * a10.getBitLength()/8, memoryState, outBytes, index);
			index += copyRegisterToArray(d8, 4 * d8.getBitLength()/8, memoryState, outBytes, index);
			index += copyRegisterToArray(a12, 4 * a12.getBitLength()/8, memoryState, outBytes, index);
			index += copyRegisterToArray(d12, 4 * d12.getBitLength()/8, memoryState, outBytes, index);	
			// write the bytes
			memoryState.setChunk(outBytes, EA_addr.getAddressSpace(), EA_addr.getOffset(), 4*16);
				
			BigInteger PCXIvalue = memoryState.getBigInteger(PCXI);
			//	PCXI[19:0] = FCX[19:0];
			//			PCXI.PCPN = ICR.CCPN;
			//			PCXI.PIE = ICR.IE;
			//			PCXI.UL = 1;	
			PCXIvalue = PCXIvalue.andNot(BigInteger.valueOf(0x000fffff)).or(FCXvalue.and(BigInteger.valueOf(0x000fffff)));
			memoryState.setValue(PCXI, PCXIvalue);
			
			// FCX[19:0] = new_FCX[19:0];	
			FCXvalue = FCXvalue.andNot(BigInteger.valueOf(0x000fffff)).or(new_FCXvalue.and(BigInteger.valueOf(0x000fffff)));
			memoryState.setValue(FCX, FCXvalue);
			
			// write to memory
			
			BigInteger LCXvalue = memoryState.getBigInteger(LCX);
		}
	}


	private class tricore_RestoreCallerState implements OpBehaviorOther {
		@Override
		public void evaluate(Emulate emu, Varnode outputVarnode, Varnode[] inputs) {
			int numArgs = inputs.length - 1;
			if (numArgs != 3) throw new LowlevelError(this.getClass().getName() + ": requires 3 inputs (FCX, LCX, PCXI), got " + numArgs);

			MemoryState memoryState = emu.getMemoryState();

			// compute new EA
			BigInteger FCXvalue = memoryState.getBigInteger(FCX);
			BigInteger PCXIvalue = memoryState.getBigInteger(PCXI);
			
			// read the value at FCX, if get nothing, then assume just increment the FCX to get to new node.
			
			// EA = {FCX.FCXS, 6'b0, FCX.FCXO, 6'b0};
			long ea = PCXIvalue.longValue();
			ea = ((ea & 0xffff0000) << 12) | ((ea & 0xffff) << 6);
			
			Address EA_addr = emu.getExecuteAddress().getNewAddress(ea);
			AddressSpace addressSpace = emu.getExecuteAddress().getAddressSpace();
			
			// read the bytes
			byte[] inBytes = new byte[4*16];
			memoryState.getChunk(inBytes, addressSpace, EA_addr.getOffset(), 4*16, true);
			//	{PCXI, PSW, A[10], A[11], D[8], D[9], D[10], D[11], A[12], A[13], A[14], A[15], D[12], D[13], D[14], D[15] = M(EA,16 * word)};
			int index = 0;
			index += copyArrayToRegister(PCXI, PCXI.getBitLength()/8, memoryState, inBytes, index);
			index += copyArrayToRegister(PSW, PSW.getBitLength()/8, memoryState, inBytes, index);
			index += copyArrayToRegister(a10, 2 * a10.getBitLength()/8, memoryState, inBytes, index);
			index += copyArrayToRegister(d8, 4 * d8.getBitLength()/8, memoryState, inBytes, index);
			index += copyArrayToRegister(a12, 4 * a12.getBitLength()/8, memoryState, inBytes, index);
			index += copyArrayToRegister(d12, 4 * d12.getBitLength()/8, memoryState, inBytes, index);	
				
			// M(EA, word) = FCX;
			memoryState.setValue(EA_addr.getAddressSpace(), EA_addr.getOffset(), 4, FCXvalue);

			// FCX[19:0] = new_FCX[19:0];
			FCXvalue = FCXvalue.andNot(BigInteger.valueOf(0x000fffff)).or(PCXIvalue.and(BigInteger.valueOf(0x000fffff)));
			memoryState.setValue(FCX, FCXvalue);
		}
	}
	
	// Helper functions
	private int copyRegisterToArray(Register reg, int len, MemoryState memoryState, byte[] outBytes, int i) {
		byte vBytes[] = new byte[len];
		int nread = memoryState.getChunk(vBytes, reg.getAddressSpace(), reg.getOffset(), len, false);
		System.arraycopy(vBytes, 0, outBytes, i, len);
		return nread;
	}
	
	private int copyArrayToRegister(Register reg, int len, MemoryState memoryState, byte[] inBytes, int i) {
		byte[] vBytes = new byte[len];
		AddressSpace spc = reg.getAddressSpace();
		System.arraycopy(inBytes, i, vBytes, 0, vBytes.length);
		memoryState.setChunk(vBytes, spc, reg.getOffset(), vBytes.length);
		return len;
	}
	
	private void cacheRegisters(Emulate emu) {
		FCX = emu.getLanguage().getRegister("FCX");
		LCX = emu.getLanguage().getRegister("LCX");
		PCXI = emu.getLanguage().getRegister("PCXI");
		PSW = emu.getLanguage().getRegister("PSW");
		a10 = emu.getLanguage().getRegister("a10");
		d8 = emu.getLanguage().getRegister("d8");
		a12 = emu.getLanguage().getRegister("a12");
		d12 = emu.getLanguage().getRegister("d12");
	}
}
