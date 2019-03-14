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
package ghidra.app.plugin.core.navigation;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.Icon;
import javax.swing.KeyStroke;

import resources.ResourceManager;

public class NextPreviousDefinedDataAction extends AbstractNextPreviousAction {

	public NextPreviousDefinedDataAction(PluginTool tool, String owner, String subGroup) {
		super(tool, "Next Data", owner, subGroup);
	}

	@Override
	protected String getNavigationTypeName() {
		return "Data";
	}

	@Override
	protected Icon getIcon() {
		return ResourceManager.loadImage("images/D.gif");
	}

	@Override
	protected KeyStroke getKeyStroke() {
		return KeyStroke.getKeyStroke(KeyEvent.VK_D, InputEvent.CTRL_DOWN_MASK |
			InputEvent.ALT_DOWN_MASK);
	}

	/**
	 * Find the beginning of the next instruction range
	 */
	@Override
	protected Address getNextAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {
		if (isDefinedDataAt(program, address)) {
			// on an instruction, we have to find a non-instruction before finding the next instruction
			address = getAddressOfNextPreviousNonDefinedData(monitor, program, address, true);
		}

		// we know address is not an instruction at this point

		return getAddressOfNextDataAfter(program, address);
	}

	@Override
	protected Address getPreviousAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		if (isDefinedDataAt(program, address)) {
			// on an instruction, we have to find a non-instruction before finding the previous instruction
			address = getAddressOfNextPreviousNonDefinedData(monitor, program, address, false);
		}

		// we know address is not at an instruction at this point

		return getAddressOfPreviousDataBefore(program, address);
	}

	private boolean isDefinedDataAt(Program program, Address address) {
		if (address == null) {
			return false;
		}
		Data data = program.getListing().getDataAt(address);
		if (data == null) {
			return false;
		}
		return data.isDefined();
	}

	private Address getAddressOfNextDataAfter(Program program, Address address) {
		if (address == null) {
			return null;
		}
		Data data = program.getListing().getDefinedDataAfter(address);
		if (data == null) {
			return null;
		}
		return data.getMinAddress();
	}

	private Address getAddressOfPreviousDataBefore(Program program, Address address) {
		if (address == null) {
			return null;
		}
		Data data = program.getListing().getDefinedDataBefore(address);
		if (data == null) {
			return null;
		}
		return data.getMinAddress();
	}

	private Address getAddressOfNextPreviousNonDefinedData(TaskMonitor monitor, Program program,
			Address address, boolean forward) throws CancelledException {

		CodeUnitIterator codeUnits = program.getListing().getCodeUnits(address, forward);
		while (codeUnits.hasNext()) {
			monitor.checkCanceled();
			CodeUnit codeUnit = codeUnits.next();
			if (codeUnit instanceof Instruction) {
				return codeUnit.getAddress();
			}
			else if (codeUnit instanceof Data) {
				if (!((Data) codeUnit).isDefined()) {
					return codeUnit.getAddress();
				}
			}
		}
		return null;
	}

}
