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
package ghidra.pcode.emulate;

import ghidra.pcode.emulate.callother.OpBehaviorOther;
import ghidra.pcode.error.LowlevelError;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.HashMap;
import java.util.Map;

/**
 * <code>EmulateInstructionStateModifier</code> defines a language specific 
 * handler to assist emulation with adjusting the current execution state,
 * providing support for custom pcodeop's (i.e., CALLOTHER).
 * The implementation of this interface must provide a public constructor which 
 * takes a single Emulate argument.
 */
public abstract class EmulateInstructionStateModifier {

	protected final Emulate emu;
	protected final Language language;

	private Map<Integer, OpBehaviorOther> pcodeOpMap;

	protected EmulateInstructionStateModifier(Emulate emu) {
		this.emu = emu;
		this.language = emu.getLanguage();
	}

	/**
	 * Register a pcodeop behavior corresponding to a CALLOTHER opcode.
	 * @param opName name as defined within language via "define pcodeop"
	 * @param pcodeOpBehavior
	 */
	protected final void registerPcodeOpBehavior(String opName, OpBehaviorOther pcodeOpBehavior) {
		if (pcodeOpMap == null) {
			pcodeOpMap = new HashMap<Integer, OpBehaviorOther>();
		}
		int numUserOps = language.getNumberOfUserDefinedOpNames();
		for (int i = 0; i < numUserOps; i++) {
			if (opName.equals(language.getUserDefinedOpName(i))) {
				pcodeOpMap.put(i, pcodeOpBehavior);
				return;
			}
		}
		throw new LowlevelError("Undefined pcodeop name: " + opName);
	}

	/**
	 * Execute a CALLOTHER op
	 * @param op
	 * @return true if corresponding pcodeop was registered and emulation support is
	 * performed, or false if corresponding pcodeop is not supported by this class.
	 * @throws LowlevelError
	 */
	public final boolean executeCallOther(PcodeOp op) throws LowlevelError {
		if (pcodeOpMap == null) {
			return false;
		}
		Varnode[] inputs = op.getInputs();
		OpBehaviorOther opBehaviorOther = pcodeOpMap.get((int) inputs[0].getOffset());
		if (opBehaviorOther == null) {
			return false;
		}
		opBehaviorOther.evaluate(emu, op.getOutput(), inputs);
		return true;
	}

	/**
	 * Emulation callback immediately before the first instruction is executed.
	 * This callback permits any language specific initializations to be performed.
	 * @param emulate
	 * @param current_address intial execute address
	 * @param contextRegisterValue initial context value or null if not applicable or unknown
	 * @throws LowlevelError
	 */
	public void initialExecuteCallback(Emulate emulate, Address current_address, RegisterValue contextRegisterValue) throws LowlevelError {
		// no default implementation
	}
	
	/**
	 * Emulation callback immediately following execution of the lastExecuteAddress.
	 * One use of this callback is to modify the flowing/future context state.
	 * @param emulate
	 * @param lastExecuteAddress
	 * @param lastExecutePcode
	 * @param lastPcodeIndex pcode index of last op or -1 if no pcode or fall-through occurred.
	 * @param currentAddress
	 * @throws LowlevelError
	 */
	public void postExecuteCallback(Emulate emulate, Address lastExecuteAddress,
			PcodeOp[] lastExecutePcode, int lastPcodeIndex, Address currentAddress)
			throws LowlevelError {
		// no default implementation
	}
}
