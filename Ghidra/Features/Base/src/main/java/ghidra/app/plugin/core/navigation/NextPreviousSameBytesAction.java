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
import java.util.Iterator;

import javax.swing.Icon;
import javax.swing.KeyStroke;

import generic.theme.GIcon;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Navigates to the same byte pattern value under the current code unit.  When negated, the search
 * will only consider a single byte, as it seems more useful to be able to skip runs of a 
 * particular byte.
 */
public class NextPreviousSameBytesAction extends AbstractNextPreviousAction {

	private static final Icon ICON = new GIcon("icon.plugin.navigation.bytes");

	NextPreviousSameBytesAction(PluginTool tool, String owner, String subGroup) {
		super(tool, "Next Matching Byte Values", owner, subGroup);
	}

	@Override
	protected Icon getIcon() {
		return ICON;
	}

	@Override
	protected KeyStroke getKeyStroke() {
		return KeyStroke.getKeyStroke(KeyEvent.VK_V, InputEvent.CTRL_DOWN_MASK |
			InputEvent.ALT_DOWN_MASK);
	}

	@Override
	protected String getNavigationTypeName() {
		return "Same Bytes Value";
	}

	@Override
	protected String getInvertedNavigationTypeName() {
		return "Different Bytes Value";
	}

	@Override
	protected Address getNextAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		if (isInverted) {
			return getNextPreviousDifferentByteValueAddress(monitor, program, address, true);
		}

		return getNextPreviousAddress(monitor, program, address, true);
	}

	@Override
	protected Address getPreviousAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException {

		if (isInverted) {
			return getNextPreviousDifferentByteValueAddress(monitor, program, address, false);
		}

		return getNextPreviousAddress(monitor, program, address, false);
	}

	private Address getNextPreviousDifferentByteValueAddress(TaskMonitor monitor, Program program,
			Address address, boolean forward) throws CancelledException {
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
			monitor.checkCancelled();
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

	private Address getNextPreviousAddress(TaskMonitor monitor, Program program,
			Address address, boolean forward) {

		Address startAddress;
		byte[] bytes;
		CodeUnit cu = program.getListing().getCodeUnitContaining(address);
		if (cu != null) {
			try {
				bytes = cu.getBytes();
			}
			catch (MemoryAccessException e) {
				Msg.debug(this, "Exception getting code unit bytes at " + cu.getAddress(), e);
				return null; // not sure if this can happen
			}

			startAddress = forward ? cu.getMaxAddress().next() : cu.getMinAddress().previous();
		}
		else {
			try {
				Memory memory = program.getMemory();
				bytes = new byte[] { memory.getByte(address) };
			}
			catch (MemoryAccessException e) {
				Msg.debug(this, "Exception getting code unit bytes at " + address, e);
				return null; // not sure if this can happen
			}

			startAddress = forward ? address.next() : address.previous();
		}

		return getNextPreviousSameBytes(monitor, program, startAddress, bytes, forward);
	}

	private Address getNextPreviousSameBytes(TaskMonitor monitor, Program program,
			Address startAddress, byte[] bytes, boolean forward) {
		Memory memory = program.getMemory();
		byte[] mask = null; // null signals to use a full mask
		AddressSetView addresses = memory.getAllInitializedAddressSet();
		if (startAddress == null) {
			return null;
		}

		Address endAddress =
			forward ? addresses.getMaxAddress() : addresses.getMinAddress().previous();
		Address matchAddress = memory.findBytes(startAddress, endAddress, bytes,
			mask, forward, monitor);
		return matchAddress;
	}

	private CodeUnit getNextPreviousCodeUnit(Program program, Address address, boolean forward) {
		if (forward) {
			return program.getListing().getDefinedCodeUnitAfter(address);
		}
		return program.getListing().getDefinedCodeUnitBefore(address);
	}

}
