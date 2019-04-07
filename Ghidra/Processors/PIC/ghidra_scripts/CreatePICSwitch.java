/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
// This script works with Sleigh PIC languages and creates a
// switch at the current instruction which should be modifying the 
// program counter.

import ghidra.app.plugin.core.analysis.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;

public class CreatePICSwitch extends GhidraScript {

	@Override
    public void run() throws Exception {

        if (currentProgram == null) {
            Msg.error(this, "Current Program is null");
        } else {
            Processor processor = currentProgram.getLanguage().getProcessor();
            if (!(processor == PicProcessor.PROCESSOR_PIC_12
                    || processor == PicProcessor.PROCESSOR_PIC_16
                    || processor == PicProcessor.PROCESSOR_PIC_17 || processor == PicProcessor.PROCESSOR_PIC_18)) {
                Msg.showError(this, null,
                        "CreatePICSwitch Script Error", "Only Sleigh PIC languages are supported!");
                return;
            }
        }
		
		boolean ok = false;
		Instruction instr = null;
		if (currentLocation != null) {
			instr = currentProgram.getListing().getInstructionAt(currentLocation.getAddress());
			if (instr != null && instr.getFlowType().isJump() && instr.getFlowType().isComputed()) {
				Address addr = instr.getMaxAddress().add(1);
				CodeUnit nextCodeUnit = currentProgram.getListing().getCodeUnitAt(addr);
				if (nextCodeUnit instanceof Data) {
					ok = !((Data)nextCodeUnit).isDefined();
				}
			}
		}
		if (!ok) {
			Msg.showError(this, null, 
					"CreatePICSwitch Script Error", "Switch may only be created when current instruction modifies register PC/PCL\n" +
					" and where the following code unit is clear.");
			return;
		}
		
		if (!PicSwitchAnalyzer.addSwitch(instr)) {
			Msg.showError(this, null, 
					"CreatePICSwitch Script Error", "Failed to identify PIC switch code");
		}
		
	}
}
