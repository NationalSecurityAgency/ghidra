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

import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

public class NextPreviousNonFunctionAction extends AbstractNextPreviousAction {

	public NextPreviousNonFunctionAction(PluginTool tool, String owner, String subGroup) {
		super(tool, "Next Non-Function", owner, subGroup);
	}

	@Override
	protected Icon getIcon() {
		return ResourceManager.loadImage("images/notF.gif");
	}

	@Override
	protected KeyStroke getKeyStroke() {
		return KeyStroke.getKeyStroke(KeyEvent.VK_N,
			InputEvent.CTRL_DOWN_MASK | InputEvent.ALT_DOWN_MASK);
	}

	@Override
	protected String getNavigationTypeName() {
		return "Instruction Not In a Function";
	}

	/**
	 * Find the beginning of the next instruction range
	 * @throws CancelledException
	 */
	@Override
	protected Address getNextAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		Function function = program.getListing().getFunctionContaining(address);
		if (function == null) {
			function = getNextFunction(program, address, true);
		}
		if (function == null) {
			return null;
		}
		return findNextInstructionAddressNotInFunction(monitor, program, function.getEntryPoint(),
			true);
	}

	@Override
	protected Address getPreviousAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		Function function = program.getListing().getFunctionContaining(address);
		if (function == null) {
			function = getNextFunction(program, address, false);
		}
		if (function == null) {
			return null;
		}
		return findNextInstructionAddressNotInFunction(monitor, program, function.getEntryPoint(),
			false);
	}

	private Address findNextInstructionAddressNotInFunction(TaskMonitor monitor, Program program,
			Address address, boolean isForward) throws CancelledException {
		Function function = program.getListing().getFunctionContaining(address);
		AddressSetView body = function.getBody();
		InstructionIterator it = program.getListing().getInstructions(address, isForward);
		while (it.hasNext()) {
			monitor.checkCanceled();
			Instruction instruction = it.next();
			Address instructionAddress = instruction.getMinAddress();
			if (!body.contains(instructionAddress)) {
				function = program.getListing().getFunctionContaining(instructionAddress);
				if (function == null) {
					return instructionAddress;
				}
				body = function.getBody();
			}
		}
		return null;
	}

	private Function getNextFunction(Program program, Address address, boolean forward) {
		FunctionIterator functionIterator = program.getListing().getFunctions(address, forward);
		if (!functionIterator.hasNext()) {
			return null;
		}
		return functionIterator.next();
	}

	@Override
	protected void gotoAddress(GoToService service, Navigatable navigatable, Address address) {
		service.goTo(navigatable, address);
	}
}
