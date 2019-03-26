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
package ghidra.app.cmd.disassemble;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

/**
 * Command for setting the fallthrough property on an instruction.
 */
public class SetFlowOverrideCmd extends BackgroundCommand {
	Address instAddr;
	AddressSetView set;
	FlowOverride flowOverride;

	/**
	 * Constructs a new command for overriding the flow  semantics of an instruction.
	 * @param instAddr the address of the instruction whose flow override is
	 * to be set.
	 * @param flowOverride the type of flow override.
	 */
	public SetFlowOverrideCmd(Address instAddr, FlowOverride flowOverride) {
		this(null, instAddr, flowOverride);
	}

	/**
	 * Constructs a new command for overriding the flow  semantics of all instructions
	 * within the address set.
	 * @param set the address set of the instructions whose flow override is
	 * to be set.
	 * @param flowOverride the type of flow override.
	 */
	public SetFlowOverrideCmd(AddressSetView set, FlowOverride flowOverride) {
		this(set, null, flowOverride);
	}

	private SetFlowOverrideCmd(AddressSetView set, Address instAddr, FlowOverride flowOverride) {
		super("Set Flow Override", true, true, true);
		this.instAddr = instAddr;
		this.set = set;
		this.flowOverride = flowOverride;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {

		Program program = (Program) obj;

		if (set != null) {
			int cnt = 0;
			// simplified monitor to avoid too much overhead
			// assumes one instruction per range
			monitor.initialize(set.getNumAddressRanges());
			for (Instruction instr : program.getListing().getInstructions(set, true)) {
				if (monitor.isCancelled()) {
					break;
				}
				instr.setFlowOverride(flowOverride);
				monitor.setProgress(++cnt);
			}
			return true;
		}

		Instruction instr = program.getListing().getInstructionAt(instAddr);
		if (instr == null) {
			return false;
		}

		if (instr.getFlowOverride() == flowOverride) {
			return true;
		}

		instr.setFlowOverride(flowOverride);

		return true;
	}

}
