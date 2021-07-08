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
import ghidra.pcode.emulate.callother.CountLeadingZerosOpBehavior;
import ghidra.pcode.error.LowlevelError;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.pcode.PcodeOp;

public class ARMEmulateInstructionStateModifier extends EmulateInstructionStateModifier {

	private Register TModeReg;
	private Register TBreg;
	private RegisterValue tMode;
	private RegisterValue aMode;

	public ARMEmulateInstructionStateModifier(Emulate emu) {
		super(emu);
		TModeReg = language.getRegister("TMode");
		TBreg = language.getRegister("ISAModeSwitch"); // generic register which mirrors TB register value
		if (TModeReg != null) {
			if (TBreg == null) {
				throw new RuntimeException("Expected language " + language.getLanguageID() +
					" to have ISAModeSwitch register defined");
			}
			tMode = new RegisterValue(TModeReg, BigInteger.ONE);
			aMode = new RegisterValue(TModeReg, BigInteger.ZERO);
		}

		registerPcodeOpBehavior("count_leading_zeroes", new CountLeadingZerosOpBehavior());

		/**
		 * We could registerPcodeOpBehavior for one or more of the following pcodeop's:
		 *  
		  Absolute
		  ClearExclusiveLocal
		  DataMemoryBarrier
		  DataSynchronizationBarrier
		  ExclusiveAccess
		  HintDebug
		  HintPreloadData
		  HintPreloadDataForWrite
		  HintPreloadInstruction
		  HintYield
		  IndexCheck
		  InstructionSynchronizationBarrier
		  ReverseBitOrder
		  SendEvent
		  SignedDoesSaturate
		  SignedSaturate
		  UnsignedDoesSaturate
		  UnsignedSaturate
		  WaitForEvent
		  WaitForInterrupt
		  coprocessor_function
		  coprocessor_function2
		  coprocessor_load
		  coprocessor_load2
		  coprocessor_loadlong
		  coprocessor_loadlong2
		  coprocessor_movefrom
		  coprocessor_movefrom2
		  coprocessor_moveto
		  coprocessor_moveto2
		  coprocessor_store
		  coprocessor_store2
		  coprocessor_storelong
		  coprocessor_storelong2
		  count_leading_zeroes
		  disableDataAbortInterrupts
		  disableFIQinterrupts
		  disableIRQinterrupts
		  enableDataAbortInterrupts
		  enableFIQinterrupts
		  enableIRQinterrupts
		  hasExclusiveAccess
		  isCurrentModePrivileged
		  isFIQinterruptsEnabled
		  isIRQinterruptsEnabled
		  isThreadMode
		  jazelle_branch
		  setAbortMode
		  setFIQMode
		  setIRQMode
		  setSupervisorMode
		  setSystemMode
		  setThreadModePrivileged
		  setUndefinedMode
		  setUserMode
		  software_breakpoint
		  software_interrupt
		 *
		 */
	}

	/**
	 * Initialize TB register based upon context-register state before first instruction is executed.
	 */
	@Override
	public void initialExecuteCallback(Emulate emulate, Address current_address, RegisterValue contextRegisterValue) throws LowlevelError {
		if (TModeReg == null) {
			return; // Thumb mode not supported
		}
		BigInteger tModeValue = BigInteger.ZERO;
		if (contextRegisterValue != null) {
			tModeValue =
				contextRegisterValue.getRegisterValue(TModeReg).getUnsignedValueIgnoreMask();
		}
		if (!BigInteger.ZERO.equals(tModeValue)) {
			tModeValue = BigInteger.ONE;
		}
		emu.getMemoryState().setValue(TBreg, tModeValue);
	}

	/**
	 * Handle odd addresses which may occur when jumping/returning indirectly
	 * to Thumb mode.  It is assumed that language will properly handle
	 * context changes during the flow of execution, we need only fix
	 * the current program counter.
	 */
	@Override
	public void postExecuteCallback(Emulate emulate, Address lastExecuteAddress,
			PcodeOp[] lastExecutePcode, int lastPcodeIndex, Address currentAddress)
			throws LowlevelError {
		if (TModeReg == null) {
			return; // Thumb mode not supported
		}
		if (lastPcodeIndex < 0) {
			// ignore fall-through condition
			return;
		}
		int lastOp = lastExecutePcode[lastPcodeIndex].getOpcode();
		if (lastOp != PcodeOp.BRANCH && lastOp != PcodeOp.CBRANCH && lastOp != PcodeOp.BRANCHIND &&
			lastOp != PcodeOp.CALL && lastOp != PcodeOp.CALLIND && lastOp != PcodeOp.RETURN) {
			// only concerned with Branch, Call or Return ops
			return;
		}
		long tbValue = emu.getMemoryState().getValue(TBreg);
		if (tbValue == 1) {
			// Thumb mode
			emu.setContextRegisterValue(tMode); // change context to be consistent with TB value
			if ((currentAddress.getOffset() & 0x1) == 1) {
				emulate.setExecuteAddress(currentAddress.previous());
			}
		}
		else if (tbValue == 0) {

			if ((currentAddress.getOffset() & 0x1) == 1) {
				throw new LowlevelError(
					"Flow to odd address occurred without setting TB register (Thumb mode)");
			}

			// ARM mode
			emu.setContextRegisterValue(aMode); // change context to be consistent with TB value
		}
	}
}
