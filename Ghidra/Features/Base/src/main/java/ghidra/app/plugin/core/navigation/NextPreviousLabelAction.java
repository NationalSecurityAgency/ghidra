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
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.Icon;
import javax.swing.KeyStroke;

import resources.ResourceManager;

public class NextPreviousLabelAction extends AbstractNextPreviousAction {

	public NextPreviousLabelAction(PluginTool tool, String owner, String subGroup) {
		super(tool, "Next Label", owner, subGroup);
	}

	@Override
	protected Icon getIcon() {
		return ResourceManager.loadImage("images/L.gif");
	}

	@Override
	protected KeyStroke getKeyStroke() {
		return KeyStroke.getKeyStroke(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK |
			InputEvent.ALT_DOWN_MASK);
	}

	@Override
	protected String getNavigationTypeName() {
		return "Label";
	}

	@Override
	protected Address getNextAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		address = getAddressOfNextCodeUnit(program, address);
		return getAddressOfNextPreviousLabel(program, address, true);
	}

	@Override
	protected Address getPreviousAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		address = getAddressOfPreviousCodeUnit(program, address);
		return getAddressOfNextPreviousLabel(program, address, false);
	}

	private Address getAddressOfNextCodeUnit(Program program, Address address) {
		CodeUnit cu = program.getListing().getCodeUnitAfter(address);
		if (cu == null) {
			return null;
		}
		return cu.getAddress();
	}

	private Address getAddressOfPreviousCodeUnit(Program program, Address address) {
		CodeUnit cu = program.getListing().getCodeUnitBefore(address);
		if (cu == null) {
			return null;
		}
		return cu.getAddress();
	}

	private Address getAddressOfNextPreviousLabel(Program program, Address address, boolean forward) {

		if (address == null) {
			return null;
		}

		Address nextDefinedLableAddress = getNextDefinedLableAddress(program, address, forward);
		Address nextReferenceToAddress = getNextReferenceToAddress(program, address, forward);

		if (nextDefinedLableAddress == null) {
			return nextReferenceToAddress;
		}
		if (nextReferenceToAddress == null) {
			return nextDefinedLableAddress;
		}

		int compare = nextDefinedLableAddress.compareTo(nextReferenceToAddress);

		if (forward) {
			return compare <= 0 ? nextDefinedLableAddress : nextReferenceToAddress;
		}

		return compare >= 0 ? nextDefinedLableAddress : nextReferenceToAddress;

	}

	private Address getNextReferenceToAddress(Program program, Address address, boolean forward) {
		ReferenceManager referenceManager = program.getReferenceManager();
		AddressIterator it = referenceManager.getReferenceDestinationIterator(address, forward);
		if (it.hasNext()) {
			return it.next();
		}
		return null;
	}

	private Address getNextDefinedLableAddress(Program program, Address address, boolean forward) {
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator it = symbolTable.getSymbolIterator(address, forward);
		if (it.hasNext()) {
			return it.next().getAddress();
		}
		return null;
	}
}
