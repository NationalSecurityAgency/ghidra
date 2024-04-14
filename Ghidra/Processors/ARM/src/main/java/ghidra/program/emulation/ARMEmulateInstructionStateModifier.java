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
		initializeRegisters();
	}

	private void initializeRegisters() {
		TModeReg = language.getRegister("TMode");
		TBreg = language.getRegister("ISAModeSwitch");
		if (TModeReg != null && TBreg == null) {
			throw new RuntimeException("Expected language " + language.getLanguageID() +
				" to have ISAModeSwitch register defined");
		}
		tMode = new RegisterValue(TModeReg, BigInteger.ONE);
		aMode = new RegisterValue(TModeReg, BigInteger.ZERO);
	}

	@Override
	public void initialExecuteCallback(Emulate emulate, Address current_address, RegisterValue contextRegisterValue) throws LowlevelError {
		if (TModeReg == null) {
			return;
		}
		BigInteger tModeValue = BigInteger.ZERO;
		if (contextRegisterValue != null) {
			tModeValue = contextRegisterValue.getRegisterValue(TModeReg).getUnsignedValueIgnoreMask();
		}
		if (!BigInteger.ZERO.equals(tModeValue)) {
			tModeValue = BigInteger.ONE;
		}
		emu.getMemoryState().setValue(TBreg, tModeValue);
	}

	@Override
	public void postExecuteCallback(Emulate emulate, Address lastExecuteAddress, PcodeOp[] lastExecutePcode, int lastPcodeIndex, Address currentAddress) throws LowlevelError {
		if (TModeReg == null || lastPcodeIndex < 0) {
			return;
		}
		int lastOp = lastExecutePcode[lastPcodeIndex].getOpcode();
		if (lastOp != PcodeOp.BRANCH && lastOp != PcodeOp.CBRANCH && lastOp != PcodeOp.BRANCHIND &&
			lastOp != PcodeOp.CALL && lastOp != PcodeOp.CALLIND && lastOp != PcodeOp.RETURN) {
			return;
		}
		long tbValue = emu.getMemoryState().getValue(TBreg);
		if (tbValue == 1) {
			handleThumbMode(emulate, currentAddress);
		} else if (tbValue == 0) {
			handleARMMode(emulate, currentAddress);
		}
	}

	private void handleThumbMode(Emulate emulate, Address currentAddress) throws LowlevelError {
		emulate.setContextRegisterValue(tMode);
		if ((currentAddress.getOffset() & 0x1) == 1) {
			emulate.setExecuteAddress(currentAddress.previous());
		}
	}

	private void handleARMMode(Emulate emulate, Address currentAddress) throws LowlevelError {
		if ((currentAddress.getOffset() & 0x1) == 1) {
			throw new LowlevelError("Flow to odd address occurred without setting TB register (Thumb mode)");
		}
		emulate.setContextRegisterValue(aMode);
	}
}
