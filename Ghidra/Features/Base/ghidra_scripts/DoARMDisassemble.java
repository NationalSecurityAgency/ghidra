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
// This script disassembles code in Arm mode
//@__params_start
//@category ARM
//@toolbar world.png
//@menupath Tools.Scripts Manager.Do A R M Disassemble
//@__params_end

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.*;
import ghidra.util.Msg;

import java.math.BigInteger;

public class DoARMDisassemble extends GhidraScript {

	@Override
	public void run() throws Exception {

		Processor armProcessor = Processor.findOrPossiblyCreateProcessor("ARM");
		if (currentProgram == null ||
			!currentProgram.getLanguage().getProcessor().equals(armProcessor)) {
			Msg.showError(this, null, "Script Error",
				"Script only supports programs with ARM language");
			return;
		}

		RegisterValue armMode = null;
		Register tmodeReg = currentProgram.getProgramContext().getRegister("TMode");
		if (tmodeReg != null) {
			armMode = new RegisterValue(tmodeReg, BigInteger.ZERO);
		}

		AddressSet set = new AddressSet();
		if (currentSelection == null || currentSelection.isEmpty()) {
			set.addRange(currentAddress, currentAddress);
		}
		else {
			set.add(currentSelection);
		}

		DisassembleCommand cmd = new DisassembleCommand(set, null, true);
		cmd.setInitialContext(armMode);
		cmd.applyTo(currentProgram, monitor);
	}

}
