
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

// Script to set CS register for ALL function definitions for the @currentProgram
//@category
import java.math.BigInteger;
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;

public class _SetSSRegForAllFuncs extends GhidraScript {

	@Override
	public void run() throws Exception {

		String addr = askString("New Value", "SS");
		if (addr.isEmpty())
			return;

		if (currentProgram != null) {
			FunctionManager fnMgr = currentProgram.getFunctionManager();
			if (fnMgr == null) {
				return;
			}

			BigInteger newAddress = new BigInteger(addr, 16);

			// update details
			doRun(fnMgr.getFunctions(true), newAddress);
		}
	}

	/**
	 * @param functions
	 * @param newAddress
	 */
	private void doRun(Iterator<Function> functions, BigInteger newAddress) {
		while (functions.hasNext()) {
			if ((getMonitor() != null) && getMonitor().isCancelled()) {
				return;
			}

			doRun(functions.next(), newAddress);
		}
	}

	/**
	 * Do for individually identified function
	 *
	 * @param func this function
	 * @param newAddress
	 */
	protected void doRun(Function func, BigInteger newAddress) {

		final String SEP = "\t";

		if (func.isThunk())
			return;

		Address addr = func.getEntryPoint();
		Instruction instr = getInstructionAt(addr);
		String strInstr = instr.getMnemonicString();
		if (!"MOV".contentEquals(strInstr))
			return;

		if (2 != instr.getNumOperands())
			return;

		if (OperandType.REGISTER != instr.getOperandType(1)
			 || !"SS".equals(instr.getRegister(1).getName()))
			return;

		Register reg = instr.getRegister(1);
		RegisterValue regVal = instr.getRegisterValue(reg);

		if (null != regVal)
			return;

		regVal = new RegisterValue(reg);
		try {
			instr.setRegisterValue(regVal.assign(reg, newAddress));
		} catch (ContextChangeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println(addr + SEP + strInstr + SEP + reg + SEP + regVal);
	}

}
