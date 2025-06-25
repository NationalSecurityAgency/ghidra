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
import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class NextPreviousFunctionAction extends AbstractNextPreviousAction {

	private static final Icon ICON = new GIcon("icon.plugin.navigation.function");

	public NextPreviousFunctionAction(PluginTool tool, String owner, String subGroup) {
		super(tool, "Next Function", owner, subGroup);
	}

	@Override
	protected Icon getIcon() {
		return ICON;
	}

	@Override
	protected KeyStroke getKeyStroke() {
		return KeyStroke.getKeyStroke(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK |
			InputEvent.ALT_DOWN_MASK);
	}

	@Override
	protected String getNavigationTypeName() {
		return "Function";
	}

	@Override
	protected String getInvertedNavigationTypeName() {
		return "Instruction Not In a Function";
	}

	@Override
	protected Address getNextAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		if (isInverted) {
			return getNextNonFunctionAddress(monitor, program, address);
		}
		Function nextFunction = getNextFunctionNotAtAddress(program, address, true);
		return nextFunction == null ? null : nextFunction.getEntryPoint();
	}

	@Override
	protected Address getPreviousAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		if (isInverted) {
			return getPreviousNonFunctionAddress(monitor, program, address);
		}

		Function function = program.getListing().getFunctionContaining(address);
		if (isInsideFunctionNotAtEntry(function, address)) {
			return function.getEntryPoint();
		}

		Function nextFunction = getNextFunctionNotAtAddress(program, address, false);
		return nextFunction == null ? null : nextFunction.getEntryPoint();
	}

	private Address getNextNonFunctionAddress(TaskMonitor monitor, Program program,
			Address address) throws CancelledException {

		Function function = program.getListing().getFunctionContaining(address);
		if (function == null) {
			function = getNextFunction(program, address, true);
		}
		if (function == null) {
			return null;
		}

		return findNextInstructionAddressNotInFunction(monitor, program, function, true);
	}

	private Address findNextInstructionAddressNotInFunction(TaskMonitor monitor, Program program,
			Function startFunction, boolean isForward) throws CancelledException {
		Function function = startFunction;
		AddressSetView body = function.getBody();
		Address address = startFunction.getEntryPoint();
		InstructionIterator it = program.getListing().getInstructions(address, isForward);
		while (it.hasNext()) {
			monitor.checkCancelled();
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

	private Address getPreviousNonFunctionAddress(TaskMonitor monitor, Program program,
			Address address) throws CancelledException {

		Function function = program.getListing().getFunctionContaining(address);
		if (function == null) {
			function = getNextFunction(program, address, false);
		}
		if (function == null) {
			return null;
		}

		return findNextInstructionAddressNotInFunction(monitor, program, function, false);
	}

	private boolean isInsideFunctionNotAtEntry(Function function, Address address) {
		if (function == null) {
			return false;
		}
		return !address.equals(function.getEntryPoint());
	}

	private Function getNextFunction(Program program, Address address, boolean forward) {
		FunctionIterator functionIterator = program.getListing().getFunctions(address, forward);
		if (!functionIterator.hasNext()) {
			return null;
		}
		return functionIterator.next();
	}

	private Function getNextFunctionNotAtAddress(Program program, Address address,
			boolean forward) {
		Memory memory = program.getMemory();
		FunctionIterator functionIterator = program.getListing().getFunctions(address, forward);

		while (functionIterator.hasNext()) {
			Function nextFunction = functionIterator.next();
			Address entryPoint = nextFunction.getEntryPoint();

			if (entryPoint.equals(address)) {
				continue;
			}
			if (memory.contains(entryPoint)) {
				return nextFunction;
			}
		}
		return null;
	}

	@Override
	protected void gotoAddress(GoToService service, Navigatable navigatable, Address address) {
		if (isInverted) {
			service.goTo(navigatable, address);
			return;
		}

		Program program = navigatable.getProgram();
		Function function = program.getListing().getFunctionAt(address);
		FunctionSignatureFieldLocation location = new FunctionSignatureFieldLocation(program,
			address, null, 0, function.getPrototypeString(false, false));

		service.goTo(navigatable, location, navigatable.getProgram());
	}
}
