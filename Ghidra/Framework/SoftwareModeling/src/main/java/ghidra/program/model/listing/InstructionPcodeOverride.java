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
package ghidra.program.model.listing;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.pcode.PcodeOverride;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;

public class InstructionPcodeOverride implements PcodeOverride {

	protected Instruction instr;

	public InstructionPcodeOverride(Instruction instr) {
		this.instr = instr;
	}

	@Override
	public Address getFallThroughOverride() {
		Address defaultFallAddr = instr.getDefaultFallThrough();
		Address fallAddr = instr.getFallThrough();
		if (fallAddr != null && !fallAddr.equals(defaultFallAddr)) {
			return fallAddr;
		}
		return null;
	}

	@Override
	public FlowOverride getFlowOverride() {
		return instr.getFlowOverride();
	}

	@Override
	public Address getInstructionStart() {
		return instr.getMinAddress();
	}

	@Override
	public Address getPrimaryCallReference() {
		for (Reference ref : instr.getReferencesFrom()) {
			if (ref.isPrimary() && ref.getReferenceType().isCall()) {
				return ref.getToAddress();
			}
		}
		return null;
	}

	@Override
	public boolean hasCallFixup(Address callDestAddr) {
		Program program = instr.getProgram();
		Function func = program.getFunctionManager().getFunctionAt(callDestAddr);
		if (func == null) {
			return false;
		}
		return (func.getCallFixup() != null);
	}

	@Override
	public InjectPayload getCallFixup(Address callDestAddr) {
		Program program = instr.getProgram();
		Function func = program.getFunctionManager().getFunctionAt(callDestAddr);
		if (func == null) {
			return null;
		}
		String fixupName = func.getCallFixup();
		if (fixupName == null) {
			return null;
		}
		InjectPayload fixup = program.getCompilerSpec().getPcodeInjectLibrary().getPayload(
			InjectPayload.CALLFIXUP_TYPE, fixupName, program, null);
		if (fixup == null) {
			Msg.warn(this, "Undefined call-fixup at " + callDestAddr + ": " + fixupName);
		}
		return fixup;
	}
}
