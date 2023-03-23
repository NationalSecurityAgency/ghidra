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
package ghidra.machinelearning.functionfinding;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * An enum representing possible interpretations of addresses 
 * (e.g. data, undefined, function start ...)
 */
public enum Interpretation {
	UNDEFINED("Undefined"),
	DATA("Data"),
	OFFCUT("Offcut"),
	BLOCK_START("Block Start"),
	WITHIN_BLOCK("Within Block"),
	FUNCTION_START("Function Start"),
	//possibly want to refine this to block starts within functions
	//and within block within functions
	FUNCTION_INTERIOR("Function Interior");

	private String display;

	Interpretation(String display) {
		this.display = display;
	}

	@Override
	public String toString() {
		return display;
	}

	/**
	 * Get the {@link Interpretation} for the given address in the given program.
	 * @param program source program
	 * @param addr address 
	 * @param monitor monitor
	 * @return interpretation of addr
	 * @throws CancelledException if user cancels monitor
	 */
	public static Interpretation getInterpretation(Program program, Address addr,
			TaskMonitor monitor) throws CancelledException {
		BasicBlockModel model = new BasicBlockModel(program);
		return getInterpretation(program, addr, model, monitor);
	}

	/**
	 * Get the {@link Interpretation} for the given address in the given program.  This
	 * method is intended to be called repeatedly in a loop, so it takes a {@link BasicBlockModel}
	 * as a parameter (which only need be created once).
	 * @param program source program
	 * @param addr address in question
	 * @param model block model
	 * @param monitor task model
	 * @return interpretation of addr
	 * @throws CancelledException if user cancels monitor
	 */
	public static Interpretation getInterpretation(Program program, Address addr,
			BasicBlockModel model, TaskMonitor monitor) throws CancelledException {
		CodeUnit cu = program.getListing().getCodeUnitContaining(addr);
		if (cu instanceof Data) {
			if (((Data) cu).isDefined()) {
				return DATA;
			}
			return UNDEFINED;
		}
		if (program.getListing().getInstructionAt(addr) == null &&
			program.getListing().getInstructionContaining(addr) != null) {
			return OFFCUT;
		}
		if (program.getFunctionManager().getFunctionAt(addr) != null) {
			return FUNCTION_START;
		}
		if (program.getFunctionManager().getFunctionContaining(addr) != null) {
			return FUNCTION_INTERIOR;
		}
		if (model.getCodeBlockAt(addr, monitor) == null) {
			return WITHIN_BLOCK;
		}
		return Interpretation.BLOCK_START;
	}
}
