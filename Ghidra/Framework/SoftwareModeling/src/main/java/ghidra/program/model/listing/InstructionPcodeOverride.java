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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.processors.sleigh.PcodeEmit;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.pcode.PcodeOverride;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;

public class InstructionPcodeOverride implements PcodeOverride {

	protected Instruction instr;
	private boolean callOverrideApplied = false;
	private boolean jumpOverrideApplied = false;
	private boolean callOtherCallOverrideApplied = false;
	private boolean callOtherJumpOverrideApplied = false;
	private Address primaryCallAddress = null;
	private List<Reference> primaryOverridingReferences;

	/**
	 * This constructor caches the primary and overriding "from" references of {@code instr}.  
	 * This cache is never updated; the assumption is that this object is short-lived 
	 * (duration of {@link PcodeEmit})  
	 * @param instr the instruction
	 */
	public InstructionPcodeOverride(Instruction instr) {
		this.instr = instr;

		primaryOverridingReferences = new ArrayList<>();
		for (Reference ref : instr.getReferencesFrom()) {
			if (!ref.isPrimary() || !ref.getToAddress().isMemoryAddress()) {
				continue;
			}
			RefType type = ref.getReferenceType();
			if (type.isOverride()) {
				primaryOverridingReferences.add(ref);
			}
			else if (type.isCall() && primaryCallAddress == null) {
				primaryCallAddress = ref.getToAddress();
			}
		}
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
	public Address getOverridingReference(RefType type) {
		if (!type.isOverride()) {
			return null;
		}
		Address overrideAddress = null;
		for (Reference ref : primaryOverridingReferences) {
			if (ref.getReferenceType().equals(type)) {
				if (overrideAddress == null) {
					overrideAddress = ref.getToAddress();
				}
				else {
					return null; //only allow one primary reference of each type
				}
			}
		}
		return overrideAddress;
	}

	@Override
	public Address getPrimaryCallReference() {
		return primaryCallAddress;
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
		InjectPayload fixup = program.getCompilerSpec()
				.getPcodeInjectLibrary()
				.getPayload(InjectPayload.CALLFIXUP_TYPE, fixupName);
		if (fixup == null) {
			Msg.warn(this, "Undefined call-fixup at " + callDestAddr + ": " + fixupName);
		}
		return fixup;
	}

	@Override
	public void setCallOverrideRefApplied() {
		callOverrideApplied = true;

	}

	@Override
	public boolean isCallOverrideRefApplied() {
		return callOverrideApplied;
	}

	@Override
	public void setJumpOverrideRefApplied() {
		jumpOverrideApplied = true;

	}

	@Override
	public boolean isJumpOverrideRefApplied() {
		return jumpOverrideApplied;
	}

	@Override
	public void setCallOtherCallOverrideRefApplied() {
		callOtherCallOverrideApplied = true;
	}

	@Override
	public boolean isCallOtherCallOverrideRefApplied() {
		return callOtherCallOverrideApplied;
	}

	@Override
	public void setCallOtherJumpOverrideRefApplied() {
		callOtherJumpOverrideApplied = true;

	}

	@Override
	public boolean isCallOtherJumpOverrideApplied() {
		return callOtherJumpOverrideApplied;
	}

	@Override
	public boolean hasPotentialOverride() {
		return !primaryOverridingReferences.isEmpty();
	}
}
