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

public class NextPreviousDefinedDataAction extends AbstractNextPreviousAction {

	private static final Icon ICON = new GIcon("icon.plugin.navigation.data");

	public NextPreviousDefinedDataAction(PluginTool tool, String owner, String subGroup) {
		super(tool, "Next Data", owner, subGroup);
	}

	@Override
	protected String getNavigationTypeName() {
		return "Data";
	}

	@Override
	protected Icon getIcon() {
		return ICON;
	}

	@Override
	protected KeyStroke getKeyStroke() {
		return KeyStroke.getKeyStroke(KeyEvent.VK_D, InputEvent.CTRL_DOWN_MASK |
			InputEvent.ALT_DOWN_MASK);
	}

	@Override
	protected Address getNextAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		if (isInverted) {
			return getNextNonDataAddress(monitor, program, address);
		}

		if (isDefinedDataAt(program, address)) {
			// on a data, find a non-data before finding the next data
			address = getAddressOfNextPreviousNonDefinedData(monitor, program, address, true);
		}

		// we know address is not an instruction at this point
		return getAddressOfNextDataAfter(program, address);
	}

	private Address getNextNonDataAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		//
		// Assumptions:
		// -if on a data, find the next instruction or undefined
		// -if not on a data, find the next data, then find the next instruction or undefined after
		//  that (this mimics the non-inverted case)
		//
		if (!isDefinedDataAt(program, address)) {
			address = getAddressOfNextDataAfter(program, address);
		}

		return getAddressOfNextPreviousNonDefinedData(monitor, program, address, true);
	}

	@Override
	protected Address getPreviousAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		if (isInverted) {
			return getPreviousNonDataAddress(monitor, program, address);
		}

		if (isDefinedDataAt(program, address)) {
			// on an data, find a non-data before finding the previous data
			address = getAddressOfNextPreviousNonDefinedData(monitor, program, address, false);
		}

		// we know address is not at an instruction at this point

		return getAddressOfPreviousDataBefore(program, address);
	}

	private Address getPreviousNonDataAddress(TaskMonitor monitor, Program program,
			Address address) throws CancelledException {

		//
		// Assumptions:
		// -if on an data, find the previous instruction or undefined
		// -if not on a data, find the previous data, then find the previous instruction or 
		//  undefined before that (this mimics the non-inverted case)
		//
		if (!isDefinedDataAt(program, address)) {
			address = getAddressOfPreviousDataBefore(program, address);
		}

		return getAddressOfNextPreviousNonDefinedData(monitor, program, address, false);
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
			monitor.checkCancelled();
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
