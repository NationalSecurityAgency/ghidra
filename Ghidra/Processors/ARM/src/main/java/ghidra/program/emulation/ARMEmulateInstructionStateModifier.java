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
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.pcode.Varnode;

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

		registerPcodeOpBehavior("setISAMode", new SetISAModeOpBehavior());

		/**
		 * We could registerPcodeOpBehavior for one or more of the following pcodeop's:
		 * <p>
		 * Absolute<br/>
		 * ClearExclusiveLocal<br/>
		 * DataMemoryBarrier<br/>
		 * DataSynchronizationBarrier<br/>
		 * ExclusiveAccess<br/>
		 * HintDebug<br/>
		 * HintPreloadData<br/>
		 * HintPreloadDataForWrite<br/>
		 * HintPreloadInstruction<br/>
		 * HintYield <br/>
		 * IndexCheck<br/>
		 * InstructionSynchronizationBarrier<br/>
		 * ReverseBitOrder<br/>
		 * SendEvent<br/>
		 * SignedDoesSaturate<br/>
		 * SignedSaturate<br/>
		 * UnsignedDoesSaturate<br/>
		 * UnsignedSaturate<br/>
		 * WaitForEvent<br/>
		 * WaitForInterrupt<br/>
		 * coprocessor_function<br/>
		 * coprocessor_function2<br/>
		 * coprocessor_load<br/>
		 * coprocessor_load2<br/>
		 * coprocessor_loadlong<br/>
		 * coprocessor_loadlong2<br/>
		 * coprocessor_movefrom<br/>
		 * coprocessor_movefrom2<br/>
		 * coprocessor_moveto<br/>
		 * coprocessor_moveto2<br/>
		 * coprocessor_store<br/>
		 * coprocessor_store2<br/>
		 * coprocessor_storelong<br/>
		 * coprocessor_storelong2<br/>
		 * disableDataAbortInterrupts<br/>
		 * disableFIQinterrupts<br/>
		 * disableIRQinterrupts<br/>
		 * enableDataAbortInterrupts<br/>
		 * enableFIQinterrupts<br/>
		 * enableIRQinterrupts<br/>
		 * hasExclusiveAccess<br/>
		 * isCurrentModePrivileged<br/>
		 * isFIQinterruptsEnabled<br/>
		 * isIRQinterruptsEnabled<br/>
		 * isThreadMode<br/>
		 * jazelle_branch<br/>
		 * setAbortMode<br/>
		 * setFIQMode<br/>
		 * setIRQMode<br/>
		 * setSupervisorMode<br/>
		 * setSystemMode<br/>
		 * setThreadModePrivileged<br/>
		 * setUndefinedMode<br/>
		 * setUserMode<br/>
		 * software_breakpoint<br/>
		 * software_interrupt<br/>
		 */
	}

	/**
	 * Initialize TB register based upon context-register state before first instruction is
	 * executed.
	 */
	@Override
	public void initialExecuteCallback(Emulate emulate, Address current_address,
			RegisterValue contextRegisterValue) throws LowlevelError {
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

	class SetISAModeOpBehavior implements OpBehaviorOther {
		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			Address currentAddress = emu.getExecuteAddress();
			long tbValue = emu.getMemoryState().getValue(TBreg);
			if (tbValue == 1) {
				// Thumb mode
				emu.setContextRegisterValue(tMode); // change context to be consistent with TB value
				if ((currentAddress.getOffset() & 0x1) == 1) {
					emu.setExecuteAddress(currentAddress.previous());
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
}
