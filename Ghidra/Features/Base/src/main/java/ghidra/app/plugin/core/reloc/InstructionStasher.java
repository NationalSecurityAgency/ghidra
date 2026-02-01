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
package ghidra.app.plugin.core.reloc;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;

public class InstructionStasher {
	private Program program;
	private Address address;
	private InstructionPrototype prototype;
	private Reference[] referencesFrom;
	private FlowOverride flowOverride;
	private Address fallthroughOverride;
	private int lengthOverride;

	private Address minAddress;

	public InstructionStasher(Program program, Address address) {
		this.program = program;
		this.address = address;
		clearAndSave();
	}

	private void clearAndSave() {
		Instruction instruction = program.getListing().getInstructionContaining(address);
		if (instruction == null) {
			return;
		}
		minAddress = instruction.getMinAddress();
		prototype = instruction.getPrototype();
		referencesFrom = instruction.getReferencesFrom();
		flowOverride = instruction.getFlowOverride();
		fallthroughOverride =
			instruction.isFallThroughOverridden() ? instruction.getFallThrough() : null;
		// Relocation data change may mutate instruction.  Do not force length of instruction 
		// unless it was previously overriden.  A value of 0 allows length to match prototoype.
		lengthOverride = instruction.isLengthOverridden() ? instruction.getLength() : 0;
		program.getListing().clearCodeUnits(minAddress, instruction.getMaxAddress(), false);
	}

	public void restore() throws CodeUnitInsertionException {
		if (prototype == null) {
			return;
		}
		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), minAddress);
		ProcessorContext context =
			new ProgramProcessorContext(program.getProgramContext(), minAddress);
		Instruction instr = program.getListing()
				.createInstruction(minAddress, prototype, buf, context, lengthOverride);

		if (flowOverride != FlowOverride.NONE) {
			instr.setFlowOverride(flowOverride);
		}

		if (fallthroughOverride != null) {
			instr.setFallThrough(fallthroughOverride);
		}

		for (Reference reference : referencesFrom) {
			if (reference.getSource() != SourceType.DEFAULT) {
				program.getReferenceManager().addReference(reference);
			}
		}

	}
}
