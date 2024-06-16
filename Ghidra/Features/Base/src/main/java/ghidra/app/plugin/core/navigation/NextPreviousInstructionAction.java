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
package ghidra.app.plugin.core.navigation;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.Icon;
import javax.swing.KeyStroke;

import generic.theme.GIcon;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class NextPreviousInstructionAction extends AbstractNextPreviousAction {

	private static final Icon ICON = new GIcon("icon.plugin.navigation.instruction");

	public NextPreviousInstructionAction(PluginTool tool, String owner, String subGroup) {
		super(tool, "Next Instruction", owner, subGroup);
	}

	@Override
	protected Icon getIcon() {
		return ICON;
	}

	@Override
	protected KeyStroke getKeyStroke() {
		return KeyStroke.getKeyStroke(KeyEvent.VK_I, InputEvent.CTRL_DOWN_MASK |
			InputEvent.ALT_DOWN_MASK);
	}

	@Override
	protected String getNavigationTypeName() {
		return "Instruction";
	}

	@Override
	protected Address getNextAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		if (isInverted) {
			return getNextNonInstructionAddress(monitor, program, address);
		}

		if (isInstructionAt(program, address)) {
			// on an instruction, find a non-instruction before finding the next instruction
			address = getAddressOfNextPreviousNonInstruction(monitor, program, address, true);
		}

		// we know address is not an instruction at this point
		return getAddressOfNextInstructionAfter(program, address);
	}

	@Override
	protected Address getPreviousAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		if (isInverted) {
			return getPreviousNonInstructionAddress(monitor, program, address);
		}

		if (isInstructionAt(program, address)) {
			// on an instruction, find a non-instruction before finding the previous instruction
			address = getAddressOfNextPreviousNonInstruction(monitor, program, address, false);
		}

		// we know address is not at an instruction at this point
		return getAddressOfPreviousInstructionBefore(program, address);
	}

	private Address getNextNonInstructionAddress(TaskMonitor monitor, Program program,
			Address address) throws CancelledException {

		//
		// Assumptions:
		// -if on an instruction, find the next data or undefined
		// -if not on an instruction, find the next instruction, then find the next data or 
		//  undefined after that (this mimics the non-inverted case)
		//
		if (!isInstructionAt(program, address)) {
			address = getAddressOfNextInstructionAfter(program, address);
		}

		return getAddressOfNextPreviousNonInstruction(monitor, program, address, true);
	}

	private Address getPreviousNonInstructionAddress(TaskMonitor monitor, Program program,
			Address address) throws CancelledException {

		//
		// Assumptions:
		// -if on an instruction, find the previous data or undefined
		// -if not on an instruction, find the previous instruction, then find the previous data or 
		//  undefined before that (this mimics the non-inverted case)
		//
		if (!isInstructionAt(program, address)) {
			address = getAddressOfPreviousInstructionBefore(program, address);
		}

		return getAddressOfNextPreviousNonInstruction(monitor, program, address, false);
	}

	private boolean isInstructionAt(Program program, Address address) {
		if (address == null) {
			return false;
		}
		return program.getListing().getInstructionAt(address) != null;
	}

	private Address getAddressOfNextInstructionAfter(Program program, Address address) {
		if (address == null) {
			return null;
		}
		Instruction instruction = program.getListing().getInstructionAfter(address);
		if (instruction == null) {
			return null;
		}
		return instruction.getMinAddress();
	}

	private Address getAddressOfPreviousInstructionBefore(Program program, Address address) {
		if (address == null) {
			return null;
		}
		Instruction instruction = program.getListing().getInstructionBefore(address);
		if (instruction == null) {
			return null;
		}
		return instruction.getMinAddress();
	}

	private Address getAddressOfNextPreviousNonInstruction(TaskMonitor monitor, Program program,
			Address address, boolean forward) throws CancelledException {

		if (address == null) {
			return null;
		}

		CodeUnitIterator codeUnits = program.getListing().getCodeUnits(address, forward);
		while (codeUnits.hasNext()) {
			monitor.checkCancelled();
			CodeUnit codeUnit = codeUnits.next();
			if (codeUnit instanceof Data) {
				return codeUnit.getAddress();
			}
		}
		return null;
	}

}
