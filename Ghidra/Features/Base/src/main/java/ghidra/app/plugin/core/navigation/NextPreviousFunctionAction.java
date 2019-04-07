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
import ghidra.program.model.listing.*;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

public class NextPreviousFunctionAction extends AbstractNextPreviousAction {

	public NextPreviousFunctionAction(PluginTool tool, String owner, String subGroup) {
		super(tool, "Next Function", owner, subGroup);
	}

	@Override
	protected Icon getIcon() {
		return ResourceManager.loadImage("images/F.gif");
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

	/**
	 * Find the beginning of the next instruction range
	 * @throws CancelledException 
	 */
	@Override
	protected Address getNextAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		Function nextFunction = getNextFunction(program, address, true);
		return nextFunction == null ? null : nextFunction.getEntryPoint();
	}

	@Override
	protected Address getPreviousAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		Function function = program.getListing().getFunctionContaining(address);
		if (isInsideFunctionNotAtEntry(function, address)) {
			return function.getEntryPoint();
		}

		Function nextFunction = getNextFunction(program, address, false);
		return nextFunction == null ? null : nextFunction.getEntryPoint();
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
		Function nextFunction = functionIterator.next();
		if (!nextFunction.getEntryPoint().equals(address)) {
			return nextFunction;
		}
		if (!functionIterator.hasNext()) {
			return null;
		}
		return functionIterator.next();
	}

	@Override
	protected void gotoAddress(GoToService service, Navigatable navigatable, Address address) {
		Program program = navigatable.getProgram();
		Function function = program.getListing().getFunctionAt(address);
		FunctionSignatureFieldLocation location = new FunctionSignatureFieldLocation(program,
			address, null, 0, function.getPrototypeString(false, false));

		service.goTo(navigatable, location, navigatable.getProgram());
	}
}
