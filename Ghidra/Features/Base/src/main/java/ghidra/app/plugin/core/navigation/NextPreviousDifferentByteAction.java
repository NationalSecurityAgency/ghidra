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

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.Iterator;

import javax.swing.Icon;
import javax.swing.KeyStroke;

import resources.ResourceManager;

public class NextPreviousDifferentByteAction extends AbstractNextPreviousAction {

	public NextPreviousDifferentByteAction(PluginTool tool, String owner, String subGroup) {
		super(tool, "Next Different Byte Value", owner, subGroup);
	}

	@Override
	protected String getNavigationTypeName() {
		return "Different Byte Value";
	}

	@Override
	protected Icon getIcon() {
		return ResourceManager.loadImage("images/V_slash.png");
	}

	@Override
	protected KeyStroke getKeyStroke() {
		return KeyStroke.getKeyStroke(KeyEvent.VK_V, InputEvent.CTRL_DOWN_MASK |
			InputEvent.ALT_DOWN_MASK);
	}

	/**
	 * Find the beginning of the next instruction range
	 */
	@Override
	protected Address getNextAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		return getNextPreviousAddress(monitor, program, address, true);
	}

	@Override
	protected Address getPreviousAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		return getNextPreviousAddress(monitor, program, address, false);
	}

	protected Address getNextPreviousAddress(TaskMonitor monitor, Program program, Address address,
			boolean forward) throws CancelledException {

		byte value = 0;
		try {
			value = program.getMemory().getByte(address);
		}
		catch (MemoryAccessException e) {
			CodeUnit codeUnit = getNextPreviousCodeUnit(program, address, forward);
			return codeUnit == null ? null : codeUnit.getAddress();
		}

		// make sure we go at least to the next code unit
		CodeUnit cu = program.getListing().getCodeUnitContaining(address);
		if (cu != null) {
			address = forward ? cu.getMaxAddress() : cu.getMinAddress();
		}

		AddressSetView initialized = program.getMemory().getAllInitializedAddressSet();
		Iterator<Address> iterator = initialized.getAddresses(address, forward);
		iterator.next();
		Memory memory = program.getMemory();
		while (iterator.hasNext()) {
			monitor.checkCanceled();
			Address addr = iterator.next();
			try {
				byte testByte = memory.getByte(addr);
				if (testByte != value) {
					return addr;
				}
			}
			catch (MemoryAccessException e) {
				// should not happen as we are only iterating over "initialized memory"
				throw new AssertException(
					"Got MemoryAccessException when iterating over intialized memeory!");
			}
		}
		return null;
	}

	private CodeUnit getNextPreviousCodeUnit(Program program, Address address, boolean forward) {
		if (forward) {
			return program.getListing().getDefinedCodeUnitAfter(address);
		}
		return program.getListing().getDefinedCodeUnitBefore(address);
	}

}
